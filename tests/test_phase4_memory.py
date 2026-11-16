"""
tests/test_phase4_memory.py - Test suite for Memory Forensics module
"""

import os
import sys
import tempfile
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.db import init_db, query_timeline
from core.memory_module import analyze_dump, find_volatility_binary


def test_volatility_binary_discovery():
    vol_bin = find_volatility_binary()
    print("Discovered Volatility binary:", vol_bin)
    assert vol_bin is not None


def test_analyze_sample_dump():
    dump_path = os.path.abspath("test_data/sample_memory.forensic")
    assert os.path.exists(dump_path)

    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "argus.db")
    conn = init_db(db_path)
    lock = threading.Lock()

    result = analyze_dump(dump_path, os_type="windows", conn=conn, lock=lock)
    assert result["success"] is True
    assert result["process_count"] == 10
    assert result["connection_count"] == 3
    assert result["malfind_count"] == 1

    # Check suspicious findings
    crit_findings = [f for f in result["suspicious_findings"] if f["severity"] == "critical"]
    assert len(crit_findings) >= 2  # mimikatz and malfind injection

    # Check database logging
    events = query_timeline(conn, lock=lock, module="memory")
    assert len(events) >= 1
    types = [e["event_type"] for e in events]
    assert "dump_analysis_completed" in types
    assert "memory_memory_injection" in types


if __name__ == "__main__":
    print("[*] Running Phase 4 (Memory forensics) tests...")
    test_volatility_binary_discovery()
    print("  [+] test_volatility_binary_discovery passed")
    test_analyze_sample_dump()
    print("  [+] test_analyze_sample_dump passed")
    print("[SUCCESS] All Phase 4 tests passed!")
