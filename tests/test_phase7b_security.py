"""
tests/test_phase7b_security.py - Security Hardening Test Suite for Project ARGUS
"""

import os
import stat
import sys
import tempfile
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.db import init_db, log_event, export_timeline, sanitize_csv_cell
from core.scan_module import is_target_allowed, normalize_target_address
from core.memory_module import validate_and_hash_dump


def test_no_shell_execution_in_repo():
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    forbidden = ["shell" + "=True", "os.system" + "(", "os.popen" + "("]
    for dirpath, dirnames, filenames in os.walk(repo_root):
        if ".git" in dirpath or ".venv" in dirpath or "__pycache__" in dirpath:
            continue
        for fn in filenames:
            if fn.endswith(".py") and fn != os.path.basename(__file__):
                fpath = os.path.join(dirpath, fn)
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    for pattern in forbidden:
                        assert pattern not in content, f"Found forbidden shell call '{pattern}' in {fpath}"


def test_odd_target_validation_forms():
    allowed, _, ip = is_target_allowed("127.0.0.1")
    assert allowed is True
    assert ip == "127.0.0.1"

    allowed, _, ip = is_target_allowed("127.1")
    assert allowed is True
    assert ip == "127.0.0.1"

    allowed, _, ip = is_target_allowed("0x7f.0.0.1")
    assert allowed is True
    assert ip == "127.0.0.1"

    allowed, _, ip = is_target_allowed("2130706433")
    assert allowed is True
    assert ip == "127.0.0.1"

    allowed, _, ip = is_target_allowed("::ffff:127.0.0.1")
    assert allowed is True
    assert ip == "127.0.0.1"

    allowed, _, ip = is_target_allowed("localhost")
    assert allowed is True

    allowed, _, _ = is_target_allowed("192.168.1.0/24")
    assert allowed is True

    allowed, msg, _ = is_target_allowed("10.0.0.0/8", allow_custom=False)
    assert allowed is False
    assert "too large" in msg

    allowed, _, _ = is_target_allowed("10.0.0.0/8", allow_custom=True)
    assert allowed is True

    allowed, _, _ = is_target_allowed("8.8.8.8", allow_custom=False)
    assert allowed is False

    allowed, _, _ = is_target_allowed("8.8.8.8", allow_custom=True)
    assert allowed is True

    allowed, msg, _ = is_target_allowed("--script=vuln")
    assert allowed is False
    assert "dash" in msg

    allowed, msg, _ = is_target_allowed("-sV")
    assert allowed is False

    allowed, _, _ = is_target_allowed("")
    assert allowed is False

    allowed, _, _ = is_target_allowed("   ")
    assert allowed is False

    allowed, _, _ = is_target_allowed("x" * 300)
    assert allowed is False


def test_csv_formula_injection_sanitization():
    assert sanitize_csv_cell("=1+1") == "'=1+1"
    assert sanitize_csv_cell("+cmd|'/C calc'!A0") == "'+cmd|'/C calc'!A0"
    assert sanitize_csv_cell("-2+3") == "'-2+3"
    assert sanitize_csv_cell("@SUM(1,2)") == "'@SUM(1,2)"
    assert sanitize_csv_cell("\tTAB") == "'\tTAB"
    assert sanitize_csv_cell("normal_text") == "normal_text"
    assert sanitize_csv_cell(123) == "123"


def test_file_permissions_and_path_security():
    temp_dir = tempfile.mkdtemp()
    try:
        db_path = os.path.join(temp_dir, "test.db")
        conn = init_db(db_path)
        lock = threading.Lock()

        log_event(conn, lock, "scan", "=cmd|'calc'!A0", "info", "=raw_payload")
        csv_path = os.path.join(temp_dir, "export.csv")
        export_timeline(conn, csv_path, format_type="csv", lock=lock)

        with open(csv_path, "r", encoding="utf-8") as f:
            content = f.read()
            assert "'=cmd|'calc'!A0" in content
            assert "'=raw_payload" in content

        mode = os.stat(csv_path).st_mode & 0o777
        assert mode in (0o600, 0o644, 0o664, 0o666)

        dummy_file = os.path.join(temp_dir, "dummy.mem")
        with open(dummy_file, "wb") as f:
            f.write(b"TEST_DUMP_DATA" * 100)

        ok, err, real_p, digest, size = validate_and_hash_dump(dummy_file)
        assert ok is True
        assert len(digest) == 64
        assert size == 1400

        ok, err, _, _, _ = validate_and_hash_dump(temp_dir)
        assert ok is False

        ok, err, _, _, _ = validate_and_hash_dump(os.path.join(temp_dir, "nonexistent.raw"))
        assert ok is False
    finally:
        import shutil
        shutil.rmtree(temp_dir)


if __name__ == "__main__":
    test_no_shell_execution_in_repo()
    test_odd_target_validation_forms()
    test_csv_formula_injection_sanitization()
    test_file_permissions_and_path_security()
    print("[SUCCESS] All Phase 7B security tests passed!")
