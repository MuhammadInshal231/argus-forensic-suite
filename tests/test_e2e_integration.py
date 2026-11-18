"""
tests/test_e2e_integration.py - Full End-to-End Test Suite for Project ARGUS
Validates Phase 0 through Phase 6 acceptance criteria in an automated pipeline.
"""

import csv
import json
import os
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.controller import ThreatForensicSuite
from core.db import init_db, log_event, query_timeline, export_timeline
from core.process_runner import run_command, StreamingProcess
from core.packet_module import list_interfaces, analyze_pcap
from core.scan_module import is_target_allowed, parse_nmap_xml
from core.memory_module import analyze_dump, find_volatility_binary


def test_phase0_deliverables():
    print("[*] Verifying Phase 0 Deliverables...")
    for req_file in ["LICENSE", "Inshal_Software_License.pdf", "ACCEPTABLE_USE.md", "requirements.txt", ".gitignore", "main.py"]:
        assert os.path.isfile(req_file), f"Missing required file: {req_file}"

    for req_dir in ["core", "gui", "workspace", "test_data"]:
        assert os.path.isdir(req_dir), f"Missing required directory: {req_dir}"

    with open("LICENSE", "r") as f:
        content = f.read()
        assert "Muhammad Inshal" in content
        assert "INSHAL SOFTWARE LICENSE" in content

    with open("ACCEPTABLE_USE.md", "r") as f:
        content = f.read()
        assert "PECA" in content
        assert "Authorized targets" in content

    print("  [✓] Phase 0 verified.")


def test_phase1_process_and_db():
    print("[*] Verifying Phase 1 Process Orchestration & Thread-Safe DB...")
    # 1. Process termination
    sp = StreamingProcess()
    sp.start(["sleep", "10"])
    assert sp.is_running
    sp.stop(timeout=1.0)
    assert not sp.is_running

    # 2. DB concurrent write test
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "test.db")
    conn = init_db(db_path)
    lock = threading.Lock()

    def writer(tid):
        for i in range(10):
            log_event(conn, lock, "scan", "test_event", "info", {"tid": tid, "i": i})

    threads = [threading.Thread(target=writer, args=(i,)) for i in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    events = query_timeline(conn, lock=lock)
    assert len(events) == 50
    print("  [✓] Phase 1 verified.")


def test_phase2_packet_analyzer():
    print("[*] Verifying Phase 2 Packet Analyzer...")
    sample_pcap = os.path.abspath("test_data/sample_traffic.pcap")
    assert os.path.exists(sample_pcap)

    res = analyze_pcap(sample_pcap)
    assert res["success"] is True
    assert res["total_packets"] == 4
    assert res["total_bytes"] > 0
    assert len(res["top_talkers"]) >= 1
    assert 23 in [p["port"] for p in res["unusual_ports"]]
    print("  [✓] Phase 2 verified.")


def test_phase3_scan_module():
    print("[*] Verifying Phase 3 Vulnerability Scanner...")
    # Guardrail check
    assert is_target_allowed("127.0.0.1")[0] is True
    assert is_target_allowed("192.168.1.1")[0] is True
    assert is_target_allowed("10.0.0.1")[0] is True
    assert is_target_allowed("172.16.0.1")[0] is True
    assert is_target_allowed("8.8.8.8")[0] is False
    assert is_target_allowed("evil.com")[0] is False

    # Risky service mapping in XML parser
    sample_xml = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sV -oX - 127.0.0.1">
  <host>
    <status state="up"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="23"><state state="open"/><service name="telnet"/></port>
      <port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
    </ports>
  </host>
</nmaprun>"""
    status, ports, meta = parse_nmap_xml(sample_xml)
    assert status == "up"
    assert len(ports) == 2
    telnet_port = next(p for p in ports if p["port"] == 23)
    assert telnet_port["severity"] == "critical"
    print("  [✓] Phase 3 verified.")


def test_phase4_memory_forensics():
    print("[*] Verifying Phase 4 Memory Forensics...")
    assert find_volatility_binary() is not None

    sample_mem = os.path.abspath("test_data/sample_memory.forensic")
    res = analyze_dump(sample_mem, os_type="windows")
    assert res["success"] is True
    assert res["process_count"] == 10
    assert res["connection_count"] == 3
    assert res["malfind_count"] == 1

    crit_findings = [f for f in res["suspicious_findings"] if f["severity"] == "critical"]
    assert len(crit_findings) >= 2  # mimikatz and malfind
    print("  [✓] Phase 4 verified.")


def test_phase5_and_6_unified_correlation_and_export():
    print("[*] Verifying Phase 5 & 6 Unified Correlation & Timeline Export...")
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "test_argus.db")
    suite = ThreatForensicSuite(db_path=db_path)

    try:
        # Run all three engines
        suite.analyze_capture(os.path.abspath("test_data/sample_traffic.pcap"))
        suite.log_custom_event(
            module="scan",
            event_type="open_port",
            severity="warning",
            details={"target": "127.0.0.1", "port": 21, "service": "ftp", "risk_assessment": "Plaintext FTP"}
        )
        suite.analyze_memory_dump(os.path.abspath("test_data/sample_memory.forensic"))

        # Query unified timeline
        events = suite.get_timeline()
        assert len(events) >= 3

        # Confirm modules present
        modules = {e["module"] for e in events}
        assert "packet" in modules
        assert "scan" in modules
        assert "memory" in modules

        # Confirm chronological ordering
        timestamps = [e["timestamp"] for e in events]
        assert timestamps == sorted(timestamps, reverse=True)

        # Test JSON export
        json_export = os.path.join(temp_dir, "timeline.json")
        suite.export_report(json_export, format_type="json")
        assert os.path.isfile(json_export)
        with open(json_export, "r") as f:
            data = json.load(f)
            assert len(data) == len(events)

        # Test CSV export
        csv_export = os.path.join(temp_dir, "timeline.csv")
        suite.export_report(csv_export, format_type="csv")
        assert os.path.isfile(csv_export)
        with open(csv_export, "r") as f:
            reader = csv.reader(f)
            rows = list(reader)
            assert len(rows) == len(events) + 1  # header + events

        print("  [✓] Phase 5 & 6 verified.")
    finally:
        suite.shutdown()


def test_gui_instantiation():
    print("[*] Verifying PyQt6 GUI Components...")
    os.environ["QT_QPA_PLATFORM"] = "offscreen"
    os.environ["QT_QPA_PLATFORMTHEME"] = ""

    from PyQt6.QtWidgets import QApplication
    from gui.main_window import MainWindow

    app = QApplication.instance() or QApplication([])
    temp_dir = tempfile.mkdtemp()
    suite = ThreatForensicSuite(db_path=os.path.join(temp_dir, "gui_test.db"))

    try:
        window = MainWindow(suite)
        assert window.tabs.count() == 4
        # Verify tab titles
        assert "Packet Analyzer" in window.tabs.tabText(0)
        assert "Vulnerability Scanner" in window.tabs.tabText(1)
        assert "Memory Forensics" in window.tabs.tabText(2)
        assert "Unified Timeline" in window.tabs.tabText(3)
        window.close()
        print("  [✓] PyQt6 GUI verified.")
    finally:
        suite.shutdown()


if __name__ == "__main__":
    print("=" * 70)
    print("RUNNING END-TO-END VERIFICATION FOR PROJECT ARGUS")
    print("=" * 70)
    test_phase0_deliverables()
    test_phase1_process_and_db()
    test_phase2_packet_analyzer()
    test_phase3_scan_module()
    test_phase4_memory_forensics()
    test_phase5_and_6_unified_correlation_and_export()
    test_gui_instantiation()
    print("=" * 70)
    print("[ALL ACCEPTANCE CRITERIA PASSED SUCCESSFULLY]")
    print("=" * 70)

