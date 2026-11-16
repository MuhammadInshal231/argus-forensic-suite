"""
core/process_runner.py - Reusable, Thread-Safe Subprocess Orchestration Layer
Orchestrates external security binaries (tshark, nmap, vol3) without freezing the GUI.
"""

import os
import signal
import subprocess
import threading
import time
from typing import Callable, List, Optional, Tuple


def run_command(
    cmd: List[str],
    timeout: Optional[int] = None,
    cwd: Optional[str] = None,
    env: Optional[dict] = None
) -> Tuple[str, str, int]:
    """
    Executes a finite command synchronously and returns (stdout, stderr, returncode).
    Thread-safe and suitable for bounded operations like Nmap scans or Volatility plugin runs.
    
    :param cmd: Command and arguments as list of strings
    :param timeout: Maximum seconds to wait before raising TimeoutExpired
    :param cwd: Optional working directory
    :param env: Optional environment variables dictionary
    :return: (stdout_str, stderr_str, return_code)
    """
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            cwd=cwd,
            env=merged_env,
            errors="replace"
        )
        return proc.stdout, proc.stderr, proc.returncode
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout if exc.stdout else ""
        stderr = exc.stderr if exc.stderr else "Process timed out"
        return stdout, stderr, -1
    except FileNotFoundError as exc:
        return "", f"Binary not found: {exc}", 127
    except Exception as exc:
        return "", f"Execution error: {exc}", 1


class StreamingProcess:
    """
    Wraps subprocess.Popen for streaming or long-running processes (e.g. live tshark capture).
    Runs reading loops in a daemon thread and provides graceful termination (SIGTERM -> SIGKILL)
    applied across the process group to prevent orphaned children (such as dumpcap).
    """

    def __init__(self):
        self.process: Optional[subprocess.Popen] = None
        self._thread: Optional[threading.Thread] = None
        self._stop_requested = threading.Event()
        self._lock = threading.Lock()
        self.cmd: List[str] = []
        self.returncode: Optional[int] = None

    @property
    def is_running(self) -> bool:
        """Returns True if the underlying process is active."""
        with self._lock:
            if self.process is None:
                return False
            poll = self.process.poll()
            return poll is None

    def start(
        self,
        cmd: List[str],
        line_callback: Optional[Callable[[str], None]] = None,
        finished_callback: Optional[Callable[[int], None]] = None,
        cwd: Optional[str] = None,
        env: Optional[dict] = None
    ) -> bool:
        """
        Spawns the process with its own process group and launches a background thread
        to read stdout/stderr line-by-line.
        """
        with self._lock:
            if self.process is not None and self.process.poll() is None:
                return False  # Already running

            self.cmd = cmd
            self._stop_requested.clear()
            self.returncode = None

            merged_env = os.environ.copy()
            if env:
                merged_env.update(env)

            try:
                # Use start_new_session=True so we can signal the entire process group
                self.process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                    cwd=cwd,
                    env=merged_env,
                    start_new_session=True,
                    errors="replace"
                )
            except Exception as exc:
                if line_callback:
                    line_callback(f"[ERROR] Failed to start process: {exc}")
                return False

        def _reader():
            try:
                if self.process and self.process.stdout:
                    for line in iter(self.process.stdout.readline, ""):
                        if not line:
                            break
                        stripped = line.rstrip("\r\n")
                        if line_callback:
                            line_callback(stripped)
            except Exception:
                pass
            finally:
                with self._lock:
                    if self.process:
                        try:
                            self.process.stdout.close()
                        except Exception:
                            pass
                        self.returncode = self.process.wait()
                    rc = self.returncode if self.returncode is not None else 0

                if finished_callback:
                    try:
                        finished_callback(rc)
                    except Exception:
                        pass

        self._thread = threading.Thread(target=_reader, daemon=True)
        self._thread.start()
        return True

    def stop(self, timeout: float = 3.0) -> int:
        """
        Gracefully terminates the process and its entire process group.
        First sends SIGINT/SIGTERM, then SIGKILL if it doesn't exit within timeout.
        Returns the process exit code.
        """
        self._stop_requested.set()
        
        with self._lock:
            proc = self.process
            if proc is None:
                return 0

        pgid = None
        try:
            pgid = os.getpgid(proc.pid)
        except (ProcessLookupError, OSError):
            pass

        # Try SIGINT / SIGTERM on process group
        try:
            if pgid:
                os.killpg(pgid, signal.SIGINT)
            else:
                proc.send_signal(signal.SIGINT)
        except Exception:
            try:
                proc.terminate()
            except Exception:
                pass

        # Wait for graceful shutdown
        start_time = time.time()
        while time.time() - start_time < timeout:
            if proc.poll() is not None:
                break
            time.sleep(0.1)

        # Force kill if still running
        if proc.poll() is None:
            try:
                if pgid:
                    os.killpg(pgid, signal.SIGKILL)
                else:
                    proc.kill()
            except Exception:
                pass

        try:
            proc.wait(timeout=1.0)
        except Exception:
            pass

        with self._lock:
            self.returncode = proc.poll()
            return self.returncode if self.returncode is not None else -1
