"""
tests/test_phase2_packet.py - Test suite for Packet Analyzer module
"""

import os
import sys
import tempfile
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.db import init_db, query_timeline
from core.packet_module import list_interfaces, analyze_pcap


def test_list_interfaces():
    ifaces = list_interfaces()
    assert len(ifaces) > 0
    names = [i["name"] for i in ifaces]
    assert "lo" in names or "any" in names


def test_analyze_pcap_sample():
    sample_path = os.path.abspath("test_data/sample_traffic.pcap")
    assert os.path.exists(sample_path)

    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "argus.db")
    conn = init_db(db_path)
    lock = threading.Lock()

    result = analyze_pcap(sample_path, conn=conn, lock=lock)
    assert result["success"] is True
    assert result["total_packets"] == 4
    assert result["total_bytes"] > 0
    assert len(result["top_talkers"]) >= 1

    # Check talker 192.168.1.50
    talker_ips = [t["ip"] for t in result["top_talkers"]]
    assert "192.168.1.50" in talker_ips

    # Check protocol breakdown
    assert "HTTPS/TLS" in result["protocols"] or "HTTP" in result["protocols"] or "TCP" in result["protocols"]

    # Check unusual port detected (port 23 telnet was sent)
    unusual_ports = [u["port"] for u in result["unusual_ports"]]
    assert 23 in unusual_ports

    # Check timeline events
    events = query_timeline(conn, lock=lock, module="packet")
    assert len(events) >= 1
    event_types = [e["event_type"] for e in events]
    assert "pcap_analysis_completed" in event_types


if __name__ == "__main__":
    print("[*] Running Phase 2 (Packet analyzer) tests...")
    test_list_interfaces()
    print("  [+] test_list_interfaces passed")
    test_analyze_pcap_sample()
    print("  [+] test_analyze_pcap_sample passed")
    print("[SUCCESS] All Phase 2 tests passed!")
