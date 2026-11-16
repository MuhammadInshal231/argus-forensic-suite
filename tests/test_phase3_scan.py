"""
tests/test_phase3_scan.py - Test suite for Nmap vulnerability scanner module
"""

import os
import sys
import tempfile
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.db import init_db, query_timeline
from core.scan_module import is_target_allowed, parse_nmap_xml, run_scan


def test_target_allowlist_guardrail():
    # Allowed
    assert is_target_allowed("127.0.0.1")[0] is True
    assert is_target_allowed("localhost")[0] is True
    assert is_target_allowed("192.168.1.100")[0] is True
    assert is_target_allowed("10.0.2.15")[0] is True
    assert is_target_allowed("172.16.5.20")[0] is True

    # Blocked
    assert is_target_allowed("8.8.8.8")[0] is False
    assert is_target_allowed("1.1.1.1")[0] is False
    assert is_target_allowed("scanme.nmap.org")[0] is False


def test_nmap_xml_parser():
    sample_xml = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV -oX - 127.0.0.1">
  <host>
    <status state="up" reason="localhost-response"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="9.6p1" method="probed">
          <cpe>cpe:/a:openbsd:openssh:9.6p1</cpe>
        </service>
      </port>
      <port protocol="tcp" portid="23">
        <state state="open" reason="syn-ack"/>
        <service name="telnet" product="Linux telnetd" version="0.17" method="probed"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="closed" reason="reset"/>
        <service name="http" method="table"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""
    status, ports = parse_nmap_xml(sample_xml)
    assert status == "up"
    assert len(ports) == 2  # Only open ports
    assert ports[0]["port"] == 22
    assert ports[0]["service"] == "ssh"
    assert ports[0]["severity"] == "info"

    assert ports[1]["port"] == 23
    assert ports[1]["service"] == "telnet"
    assert ports[1]["severity"] == "critical"  # Risky service identified


def test_real_scan_localhost():
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "argus.db")
    conn = init_db(db_path)
    lock = threading.Lock()

    # Fast scan localhost with -sT
    res = run_scan("127.0.0.1", scan_type="-sT -F", conn=conn, lock=lock, timeout=30)
    assert res["success"] is True
    assert res["host_status"] in ("up", "unknown")
    
    events = query_timeline(conn, lock=lock, module="scan")
    assert len(events) >= 1
    assert any(e["event_type"] == "host_scan_completed" for e in events)


if __name__ == "__main__":
    print("[*] Running Phase 3 (Nmap scan) tests...")
    test_target_allowlist_guardrail()
    print("  [+] test_target_allowlist_guardrail passed")
    test_nmap_xml_parser()
    print("  [+] test_nmap_xml_parser passed")
    test_real_scan_localhost()
    print("  [+] test_real_scan_localhost passed")
    print("[SUCCESS] All Phase 3 tests passed!")
