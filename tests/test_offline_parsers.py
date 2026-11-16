"""
tests/test_offline_parsers.py - Standalone offline parser and concurrency tests (No live external tools required)
"""

import json
import os
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.db import init_db, log_event, query_timeline
from core.memory_module import _normalize_pslist
from core.process_runner import run_command, StreamingProcess
from core.scan_module import parse_nmap_xml


def test_offline_nmap_parser():
    xml_path = os.path.abspath("test_data/sample_nmap.xml")
    with open(xml_path, "r", encoding="utf-8") as f:
        xml_content = f.read()

    status, ports, meta = parse_nmap_xml(xml_content)
    assert status == "up"
    assert len(ports) == 4
    port_ids = {p["port"] for p in ports}
    assert port_ids == {53, 80, 443, 22}

    p80 = next(p for p in ports if p["port"] == 80)
    assert p80["service"] == "http"
    assert p80["severity"] == "medium"

    p53 = next(p for p in ports if p["port"] == 53)
    assert p53["service"] == "domain"
    assert p53["version"] == "dnsmasq 2.85"


def test_offline_volatility_parsers():
    win_path = os.path.abspath("test_data/sample_volatility_windows.json")
    with open(win_path, "r", encoding="utf-8") as f:
        win_raw = json.load(f)

    win_procs = _normalize_pslist(win_raw)
    assert len(win_procs) == 4
    assert any(p["name"] == "mimikatz.exe" and p["pid"] == 4920 for p in win_procs)
    assert any(p["name"] == "System" and p["pid"] == 4 for p in win_procs)

    linux_path = os.path.abspath("test_data/sample_volatility_linux.json")
    with open(linux_path, "r", encoding="utf-8") as f:
        linux_raw = json.load(f)

    linux_procs = _normalize_pslist(linux_raw)
    assert len(linux_procs) == 3
    assert any(p["name"] == "systemd" and p["pid"] == 1 for p in linux_procs)
    assert any(p["name"] == "nc" and p["pid"] == 1337 for p in linux_procs)


def test_concurrent_db_writes():
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "concurrent_test.db")
    conn = init_db(db_path)
    lock = threading.Lock()

    thread_count = 10
    writes_per_thread = 20
    threads = []
    errors = []

    def worker(tid: int):
        try:
            for i in range(writes_per_thread):
                log_event(
                    conn,
                    lock,
                    module="scan",
                    event_type=f"concurrent_test_{tid}",
                    severity="info",
                    details={"thread": tid, "seq": i}
                )
        except Exception as exc:
            errors.append(exc)

    for tid in range(thread_count):
        t = threading.Thread(target=worker, args=(tid,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    assert len(errors) == 0
    all_events = query_timeline(conn, lock=lock, limit=500)
    assert len(all_events) == thread_count * writes_per_thread


def test_process_runner_lifecycle():
    stdout, stderr, rc = run_command(["echo", "TEST_EXEC_OK"])
    assert rc == 0
    assert "TEST_EXEC_OK" in stdout

    start_time = time.time()
    stdout_t, stderr_t, rc_t = run_command(["sleep", "5"], timeout=1)
    duration = time.time() - start_time
    assert rc_t == -1
    assert duration < 3.0
    assert "timed out" in stderr_t.lower()

    lines_collected = []
    def on_line(line: str):
        lines_collected.append(line)

    proc = StreamingProcess()
    started = proc.start(
        ["python3", "-c", "import time; print('LINE1', flush=True); time.sleep(0.1); print('LINE2', flush=True); time.sleep(10)"],
        line_callback=on_line
    )
    assert started is True
    time.sleep(0.5)
    assert proc.is_running
    stop_rc = proc.stop(timeout=2)
    assert not proc.is_running
    assert len(lines_collected) >= 1


if __name__ == "__main__":
    print("[*] Running Offline Parser and Hardening Test Suite...")
    test_offline_nmap_parser()
    print("  [+] test_offline_nmap_parser passed")
    test_offline_volatility_parsers()
    print("  [+] test_offline_volatility_parsers passed")
    test_concurrent_db_writes()
    print("  [+] test_concurrent_db_writes passed")
    test_process_runner_lifecycle()
    print("  [+] test_process_runner_lifecycle passed")
    print("[SUCCESS] All offline tests passed!")
