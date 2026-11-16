"""
tests/test_phase1.py - Verification tests for Phase 1 process runner and DB
"""

import os
import sys
import shutil
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.db import init_db, log_event, query_timeline, get_timeline_stats
from core.process_runner import run_command, StreamingProcess


def test_run_command():
    stdout, stderr, rc = run_command(["echo", "ARGUS_TEST_OK"])
    assert rc == 0
    assert "ARGUS_TEST_OK" in stdout


def test_streaming_process_stop():
    sp = StreamingProcess()
    lines = []
    # Ping 127.0.0.1 20 times (20 seconds)
    started = sp.start(["ping", "-c", "20", "127.0.0.1"], line_callback=lambda l: lines.append(l))
    assert started
    assert sp.is_running
    time.sleep(1.0)
    assert len(lines) > 0
    rc = sp.stop(timeout=2.0)
    assert not sp.is_running
    # Verify process is terminated
    assert rc is not None


def test_thread_safe_db_concurrent_writes():
    temp_dir = tempfile.mkdtemp()
    try:
        db_path = os.path.join(temp_dir, "test.db")
        conn = init_db(db_path)
        lock = threading.Lock()

        def worker(thread_id, count):
            for i in range(count):
                log_event(
                    conn,
                    lock,
                    module="scan" if thread_id % 2 == 0 else "packet",
                    event_type=f"test_event_{thread_id}_{i}",
                    severity="info" if i % 2 == 0 else "warning",
                    details={"worker": thread_id, "index": i}
                )

        threads = []
        for t_id in range(4):
            t = threading.Thread(target=worker, args=(t_id, 25))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        events = query_timeline(conn, lock=lock)
        assert len(events) == 100, f"Expected 100 events, got {len(events)}"

        stats = get_timeline_stats(conn, lock=lock)
        assert stats["total_events"] == 100
        assert stats["by_module"]["scan"] == 50
        assert stats["by_module"]["packet"] == 50
    finally:
        shutil.rmtree(temp_dir)


if __name__ == "__main__":
    print("[*] Running Phase 1 tests...")
    test_run_command()
    print("  [+] test_run_command passed")
    test_streaming_process_stop()
    print("  [+] test_streaming_process_stop passed")
    test_thread_safe_db_concurrent_writes()
    print("  [+] test_thread_safe_db_concurrent_writes passed")
    print("[SUCCESS] All Phase 1 tests passed!")
