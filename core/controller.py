"""
core/controller.py - ThreatForensicSuite (Model / Facade Controller)
Decoupled controller uniting Packet Analyzer, Nmap Scanner, and Memory Forensics.
Contains zero GUI dependencies, enabling independent testing, headless CLI use, and clean MVC separation.
"""

import os
import threading
from typing import Any, Callable, Dict, List, Optional, Tuple

from core.db import export_timeline, get_timeline_stats, init_db, log_event, query_timeline
from core.memory_module import analyze_dump
from core.packet_module import analyze_pcap, list_interfaces, start_capture, stop_capture
from core.process_runner import StreamingProcess
from core.scan_module import is_target_allowed, run_scan


class ThreatForensicSuite:
    """
    Unified Orchestrator for Project ARGUS.
    Implements the Facade Pattern over the three underlying security engines.
    """

    def __init__(self, db_path: str = "workspace/argus.db"):
        self.db_path = os.path.abspath(db_path)
        self.lock = threading.Lock()
        self.conn = init_db(self.db_path)
        
        # State tracking for active live packet capture
        self._capture_process: Optional[StreamingProcess] = None
        self._current_pcap_path: Optional[str] = None
        self._capture_start_time: Optional[float] = None

    # ---------------------------------------------------------
    # System & Database Methods
    # ---------------------------------------------------------
    def log_custom_event(
        self,
        module: str,
        event_type: str,
        severity: str,
        details: Dict[str, Any]
    ) -> int:
        """Logs a custom event to the unified timeline."""
        return log_event(self.conn, self.lock, module, event_type, severity, details)

    def get_timeline(
        self,
        module: Optional[str] = None,
        severity: Optional[str] = None,
        since: Optional[str] = None,
        limit: Optional[int] = None,
        search: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Queries events across all modules from the unified timeline."""
        return query_timeline(
            self.conn,
            lock=self.lock,
            module=module,
            severity=severity,
            since=since,
            limit=limit,
            search=search
        )

    def get_statistics(self) -> Dict[str, Any]:
        """Returns overall event statistics grouped by module and severity."""
        return get_timeline_stats(self.conn, lock=self.lock)

    def export_report(
        self,
        output_filepath: str,
        format_type: str = "json",
        module: Optional[str] = None,
        severity: Optional[str] = None
    ) -> str:
        """Exports the timeline to a structured JSON or CSV forensic report."""
        return export_timeline(
            self.conn,
            filepath=output_filepath,
            format_type=format_type,
            lock=self.lock,
            module=module,
            severity=severity
        )

    # ---------------------------------------------------------
    # Module A: Packet Analyzer
    # ---------------------------------------------------------
    def get_network_interfaces(self) -> List[Dict[str, str]]:
        """Discovers capture interfaces available on the system."""
        return list_interfaces()

    def start_packet_capture(
        self,
        interface: str = "lo",
        duration: Optional[int] = None,
        bpf_filter: Optional[str] = None,
        output_pcap: Optional[str] = None,
        line_callback: Optional[Callable[[str], None]] = None,
        finished_callback: Optional[Callable[[int], None]] = None
    ) -> Tuple[str, bool]:
        """
        Starts a live packet capture.
        """
        if self._capture_process and self._capture_process.is_running:
            return self._current_pcap_path or "", False

        pcap_path, proc = start_capture(
            interface=interface,
            duration=duration,
            bpf_filter=bpf_filter,
            output_pcap=output_pcap,
            line_callback=line_callback,
            finished_callback=finished_callback
        )
        self._current_pcap_path = pcap_path
        self._capture_process = proc
        return pcap_path, True

    def stop_packet_capture(self) -> Tuple[Optional[str], int]:
        """
        Stops any ongoing packet capture cleanly.
        Returns (pcap_path, exit_code).
        """
        if self._capture_process and self._capture_process.is_running:
            rc = stop_capture(self._capture_process)
            path = self._current_pcap_path
            self._capture_process = None
            return path, rc
        return self._current_pcap_path, 0

    def is_capturing(self) -> bool:
        """Returns True if a live capture is currently executing."""
        return bool(self._capture_process and self._capture_process.is_running)

    def analyze_capture(
        self,
        pcap_path: str,
        display_filter: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Runs forensic traffic analysis on a .pcap file and logs results to DB.
        """
        return analyze_pcap(
            pcap_path=pcap_path,
            conn=self.conn,
            lock=self.lock,
            display_filter=display_filter
        )

    # ---------------------------------------------------------
    # Module B: Vulnerability Scanner
    # ---------------------------------------------------------
    def validate_target(self, target: str, allow_custom: bool = False) -> Tuple[bool, str]:
        """Checks target against authorized lab allowlist and dynamically detected host IPs."""
        return is_target_allowed(target, allow_custom=allow_custom)

    def scan_target(
        self,
        target: str,
        scan_type: str = "-sV -T4 --open -Pn",
        timeout: int = 180,
        allow_custom: bool = False,
        line_callback: Optional[Callable[[str], None]] = None
    ) -> Dict[str, Any]:
        """
        Runs an Nmap vulnerability/port scan against an authorized target.
        """
        return run_scan(
            target=target,
            scan_type=scan_type,
            conn=self.conn,
            lock=self.lock,
            timeout=timeout,
            allow_custom=allow_custom,
            line_callback=line_callback
        )

    # ---------------------------------------------------------
    # Module C: Memory Forensics
    # ---------------------------------------------------------
    def analyze_memory_dump(
        self,
        dump_path: str,
        os_type: str = "windows",
        timeout: int = 180
    ) -> Dict[str, Any]:
        """
        Performs memory forensics (processes, net sockets, malfind code injection).
        """
        return analyze_dump(
            dump_path=dump_path,
            os_type=os_type,
            conn=self.conn,
            lock=self.lock,
            timeout=timeout
        )

    # ---------------------------------------------------------
    # Teardown & Lifecycle
    # ---------------------------------------------------------
    def shutdown(self):
        """
        Gracefully terminates background processes and closes DB connections.
        Ensures no orphaned tshark or nmap processes are left behind.
        """
        if self._capture_process and self._capture_process.is_running:
            try:
                self._capture_process.stop()
            except Exception:
                pass
            self._capture_process = None

        if self.conn:
            try:
                self.conn.close()
            except Exception:
                pass

