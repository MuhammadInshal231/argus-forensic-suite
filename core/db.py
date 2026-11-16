"""
core/db.py - Unified SQLite Database Layer for Project ARGUS
Provides thread-safe access and schema management for chronological event logging.
"""

import json
import os
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    module TEXT NOT NULL,
    event_type TEXT NOT NULL,
    severity TEXT,
    details TEXT NOT NULL,
    timestamp TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_module ON events(module);
"""

# Global lock fallback if no explicit lock is supplied
_DEFAULT_DB_LOCK = threading.Lock()


def init_db(db_path: str = "workspace/argus.db") -> sqlite3.Connection:
    """
    Initializes the SQLite database with WAL mode and creates required tables and indexes.
    Uses check_same_thread=False for multi-threaded GUI / background worker access.
    """
    dirname = os.path.dirname(db_path)
    if dirname:
        os.makedirs(dirname, exist_ok=True)

    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row

    with conn:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.executescript(SCHEMA_SQL)

    return conn


def log_event(
    conn: sqlite3.Connection,
    lock: Optional[threading.Lock],
    module: str,
    event_type: str,
    severity: str,
    details: Dict[str, Any] | str,
    timestamp: Optional[str] = None
) -> int:
    """
    Thread-safely logs a security/forensic event into the unified timeline.
    
    :param conn: sqlite3 Connection object
    :param lock: threading.Lock instance (uses fallback lock if None)
    :param module: 'packet' | 'scan' | 'memory'
    :param event_type: Descriptive type, e.g. 'risky_service', 'malfind_injection'
    :param severity: 'info' | 'warning' | 'critical'
    :param details: Dictionary or JSON string containing event metadata
    :param timestamp: ISO 8601 UTC timestamp string (defaults to current time)
    :return: The row id of the inserted event
    """
    use_lock = lock if lock is not None else _DEFAULT_DB_LOCK
    
    if timestamp is None:
        timestamp = datetime.now(timezone.utc).isoformat()

    if isinstance(details, (dict, list)):
        details_str = json.dumps(details, ensure_ascii=False)
    else:
        details_str = str(details)

    sql = """
    INSERT INTO events (module, event_type, severity, details, timestamp)
    VALUES (?, ?, ?, ?, ?)
    """

    with use_lock:
        cursor = conn.cursor()
        cursor.execute(sql, (module, event_type, severity, details_str, timestamp))
        conn.commit()
        return cursor.lastrowid or 0


def query_timeline(
    conn: sqlite3.Connection,
    lock: Optional[threading.Lock] = None,
    module: Optional[str] = None,
    severity: Optional[str] = None,
    since: Optional[str] = None,
    limit: Optional[int] = None,
    search: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Queries events from the unified timeline, sorted chronologically descending or ascending.
    Returns list of dict representations with parsed JSON details where applicable.
    """
    use_lock = lock if lock is not None else _DEFAULT_DB_LOCK

    clauses = []
    params: List[Any] = []

    if module and module.lower() != "all":
        clauses.append("module = ?")
        params.append(module.lower())

    if severity and severity.lower() != "all":
        clauses.append("LOWER(severity) = ?")
        params.append(severity.lower())

    if since:
        clauses.append("timestamp >= ?")
        params.append(since)

    if search:
        clauses.append("(event_type LIKE ? OR details LIKE ?)")
        search_pattern = f"%{search}%"
        params.extend([search_pattern, search_pattern])

    where_sql = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    limit_sql = f"LIMIT {int(limit)}" if limit is not None else ""

    query = f"""
    SELECT id, module, event_type, severity, details, timestamp
    FROM events
    {where_sql}
    ORDER BY timestamp DESC
    {limit_sql}
    """

    with use_lock:
        cursor = conn.cursor()
        cursor.execute(query, params)
        rows = cursor.fetchall()

    results = []
    for row in rows:
        raw_details = row["details"]
        try:
            parsed_details = json.loads(raw_details)
        except Exception:
            parsed_details = raw_details

        results.append({
            "id": row["id"],
            "module": row["module"],
            "event_type": row["event_type"],
            "severity": row["severity"],
            "details": parsed_details,
            "raw_details": raw_details,
            "timestamp": row["timestamp"],
        })

    return results


def export_timeline(
    conn: sqlite3.Connection,
    filepath: str,
    format_type: str = "json",
    lock: Optional[threading.Lock] = None,
    module: Optional[str] = None,
    severity: Optional[str] = None
) -> str:
    """
    Exports the chronological timeline to JSON or CSV for portfolio and forensic reports.
    """
    events = query_timeline(conn, lock=lock, module=module, severity=severity)
    
    os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)

    if format_type.lower() == "csv":
        import csv
        with open(filepath, "w", newline="", encoding="utf-8") as csvfile:
            fieldnames = ["id", "timestamp", "module", "event_type", "severity", "details"]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for ev in events:
                writer.writerow({
                    "id": ev["id"],
                    "timestamp": ev["timestamp"],
                    "module": ev["module"],
                    "event_type": ev["event_type"],
                    "severity": ev["severity"],
                    "details": ev["raw_details"]
                })
    else:
        # Default to JSON
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(events, f, indent=2, ensure_ascii=False)

    return filepath


def get_timeline_stats(
    conn: sqlite3.Connection,
    lock: Optional[threading.Lock] = None
) -> Dict[str, Any]:
    """
    Computes statistical counts per module and severity for the dashboard status indicators.
    """
    use_lock = lock if lock is not None else _DEFAULT_DB_LOCK

    with use_lock:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) AS total FROM events")
        total = cursor.fetchone()["total"]

        cursor.execute("SELECT module, COUNT(*) as count FROM events GROUP BY module")
        by_module = {r["module"]: r["count"] for r in cursor.fetchall()}

        cursor.execute("SELECT severity, COUNT(*) as count FROM events GROUP BY severity")
        by_severity = {r["severity"]: r["count"] for r in cursor.fetchall()}

    return {
        "total_events": total,
        "by_module": by_module,
        "by_severity": by_severity
    }
