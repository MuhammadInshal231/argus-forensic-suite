"""
tests/test_phase1.py - Alias for tests/test_phase1_process.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.test_phase1_process import (
    test_run_command,
    test_streaming_process_stop,
    test_thread_safe_db_concurrent_writes,
)

if __name__ == "__main__":
    print("[*] Running Phase 1 tests...")
    test_run_command()
    print("  [+] test_run_command passed")
    test_streaming_process_stop()
    print("  [+] test_streaming_process_stop passed")
    test_thread_safe_db_concurrent_writes()
    print("  [+] test_thread_safe_db_concurrent_writes passed")
    print("[SUCCESS] All Phase 1 tests passed!")
