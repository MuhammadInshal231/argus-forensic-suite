"""
tests/test_phase7c_correctness.py - Verification suite for Phase 7C Correctness Fixes
"""

import os
import sys
import tempfile
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.db import (
    init_db,
    log_event,
    migrate_db_severities,
    normalize_severity,
    query_timeline,
    VALID_SEVERITIES,
)
from core.memory_module import (
    analyze_dump,
    detect_os,
    format_volatility_error,
    LINUX_PLUGINS,
    normalize_iso_utc,
    WINDOWS_PLUGINS,
)


def test_severity_vocabulary_and_migration():
    assert set(VALID_SEVERITIES) == {"info", "low", "medium", "high", "critical"}
    assert normalize_severity("warning") == "medium"
    assert normalize_severity("WARN") == "medium"
    assert normalize_severity("crit") == "critical"
    assert normalize_severity("error") == "high"
    assert normalize_severity("critical") == "critical"
    assert normalize_severity("high") == "high"
    assert normalize_severity("medium") == "medium"
    assert normalize_severity("low") == "low"
    assert normalize_severity("info") == "info"
    assert normalize_severity("unknown_xyz") == "info"

    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "mig_test.db")
    conn = init_db(db_path)
    lock = threading.Lock()

    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO events (module, event_type, severity, details, timestamp) VALUES (?, ?, ?, ?, ?)",
        ("scan", "test_legacy", "warning", "legacy finding", "2026-11-16T12:00:00Z")
    )
    conn.commit()

    migrated_count = migrate_db_severities(conn, lock=lock)
    assert migrated_count >= 1

    events = query_timeline(conn, lock=lock, search="test_legacy")
    assert len(events) == 1
    assert events[0]["severity"] == "medium"


def test_memory_os_detection_and_plugin_sets():
    sample_path = os.path.abspath("test_data/sample_memory.forensic")
    detected = detect_os(sample_path)
    assert detected == "windows"

    assert "windows.pslist" in WINDOWS_PLUGINS
    assert "windows.psscan" in WINDOWS_PLUGINS
    assert "windows.malfind" in WINDOWS_PLUGINS
    assert "linux.pslist" in LINUX_PLUGINS
    assert "linux.sockstat" in LINUX_PLUGINS
    assert "linux.bash" in LINUX_PLUGINS


def test_missing_symbol_and_volatility_error_formatting():
    msg_sym = format_volatility_error("Volatility 3 Framework\nUnsatisfied requirement: linux.banner symbol table not found", "")
    assert "symbol table" in msg_sym.lower()
    assert "Linux symbol table missing" in msg_sym

    msg_layer = format_volatility_error("No suitable layer could be loaded for the given image", "")
    assert "Unsupported memory format" in msg_layer

    msg_timeout = format_volatility_error("Command timed out after 180 seconds", "")
    assert "timed out" in msg_timeout.lower()


def test_hidden_process_correlation_rule():
    sample_path = os.path.abspath("test_data/sample_memory.forensic")
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "mem_test.db")
    conn = init_db(db_path)
    lock = threading.Lock()

    res = analyze_dump(sample_path, os_type="windows", conn=conn, lock=lock)
    assert res["success"] is True
    assert res["hidden_process_count"] >= 1

    hidden_entries = res["hidden_processes"]
    assert any(hp["pid"] == 9999 for hp in hidden_entries)

    hidden_findings = [f for f in res["suspicious_findings"] if f["category"] == "hidden_process"]
    assert len(hidden_findings) >= 1
    assert hidden_findings[0]["severity"] == "medium"
    assert "possible hidden" in hidden_findings[0]["title"].lower()

    events = query_timeline(conn, lock=lock, module="memory")
    hidden_events = [e for e in events if e["event_type"] == "memory_hidden_process"]
    assert len(hidden_events) >= 1
    assert hidden_events[0]["severity"] == "medium"


def test_utc_timestamps_and_tentative_wording():
    ts = normalize_iso_utc("2026-11-16 08:24:45")
    assert "T" in ts
    assert ts.endswith("+00:00") or ts.endswith("Z")

    sample_path = os.path.abspath("test_data/sample_memory.forensic")
    res = analyze_dump(sample_path, os_type="windows")
    for f in res["suspicious_findings"]:
        t_lower = f["title"].lower()
        d_lower = f["details"].lower()
        assert ("possible" in t_lower or "unusual" in t_lower or "injected" in t_lower)
        assert "requires review" in d_lower


def test_timeline_pagination_and_query_limits():
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "limit_test.db")
    conn = init_db(db_path)
    lock = threading.Lock()

    for i in range(25):
        log_event(conn, lock, "scan", "test_event", "info", {"index": i})

    events_10 = query_timeline(conn, lock=lock, limit=10)
    assert len(events_10) == 10

    events_5 = query_timeline(conn, lock=lock, limit=5)
    assert len(events_5) == 5

    events_all = query_timeline(conn, lock=lock, limit=None)
    assert len(events_all) == 25


if __name__ == "__main__":
    print("[*] Running Phase 7C (Correctness fixes) tests...")
    test_severity_vocabulary_and_migration()
    print("  [+] test_severity_vocabulary_and_migration passed")
    test_memory_os_detection_and_plugin_sets()
    print("  [+] test_memory_os_detection_and_plugin_sets passed")
    test_missing_symbol_and_volatility_error_formatting()
    print("  [+] test_missing_symbol_and_volatility_error_formatting passed")
    test_hidden_process_correlation_rule()
    print("  [+] test_hidden_process_correlation_rule passed")
    test_utc_timestamps_and_tentative_wording()
    print("  [+] test_utc_timestamps_and_tentative_wording passed")
    test_timeline_pagination_and_query_limits()
    print("  [+] test_timeline_pagination_and_query_limits passed")
    print("[SUCCESS] All Phase 7C correctness tests passed!")

