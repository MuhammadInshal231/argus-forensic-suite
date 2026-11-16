"""
tests/test_controller.py - Test suite for ThreatForensicSuite Facade
"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.controller import ThreatForensicSuite


def test_suite_facade():
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "test_argus.db")

    suite = ThreatForensicSuite(db_path=db_path)
    try:
        # Interfaces
        ifaces = suite.get_network_interfaces()
        assert len(ifaces) > 0

        # Target validation
        ok, msg = suite.validate_target("127.0.0.1")
        assert ok is True
        ok, msg = suite.validate_target("8.8.8.8")
        assert ok is False

        # Pcap analysis
        sample_pcap = os.path.abspath("test_data/sample_traffic.pcap")
        pcap_res = suite.analyze_capture(sample_pcap)
        assert pcap_res["success"] is True

        # Memory analysis
        sample_mem = os.path.abspath("test_data/sample_memory.forensic")
        mem_res = suite.analyze_memory_dump(sample_mem)
        assert mem_res["success"] is True

        # Timeline integration query
        timeline = suite.get_timeline()
        assert len(timeline) >= 2
        modules_in_timeline = {e["module"] for e in timeline}
        assert "packet" in modules_in_timeline
        assert "memory" in modules_in_timeline

        # Export report
        export_path = os.path.join(temp_dir, "report.json")
        saved = suite.export_report(export_path, format_type="json")
        assert os.path.exists(saved)
        assert os.path.getsize(saved) > 0

        # Stats
        stats = suite.get_statistics()
        assert stats["total_events"] >= 2
    finally:
        suite.shutdown()


if __name__ == "__main__":
    print("[*] Running ThreatForensicSuite facade tests...")
    test_suite_facade()
    print("[SUCCESS] ThreatForensicSuite facade tests passed!")
