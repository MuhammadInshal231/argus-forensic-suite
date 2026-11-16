"""
core/db.py - Unified SQLite Database Layer for Project ARGUS
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

_DEFAULT_DB_LOCK = threading.Lock()


VALID_SEVERITIES = ("info", "low", "medium", "high", "critical")

SEVERITY_MIGRATION_MAP = {
    "warning": "medium",
    "warn": "medium",
    "err": "high",
    "error": "high",
    "crit": "critical",
}


def normalize_severity(sev: Optional[str]) -> str:
    if not sev:
        return "info"
    s = sev.lower().strip()
    if s in SEVERITY_MIGRATION_MAP:
        return SEVERITY_MIGRATION_MAP[s]
    if s in VALID_SEVERITIES:
        return s
    return "info"


def migrate_db_severities(conn: sqlite3.Connection, lock: Optional[threading.Lock] = None) -> int:
    use_lock = lock if lock is not None else _DEFAULT_DB_LOCK
    total_migrated = 0
    with use_lock:
        cursor = conn.cursor()
        for old_sev, new_sev in SEVERITY_MIGRATION_MAP.items():
            cursor.execute("UPDATE events SET severity = ? WHERE LOWER(severity) = ?", (new_sev, old_sev))
            total_migrated += cursor.rowcount
        conn.commit()
    return total_migrated


def sanitize_csv_cell(val: Any) -> str:
    s = str(val) if val is not None else ""
    if s and s[0] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + s
    return s


def init_db(db_path: str = "workspace/argus.db") -> sqlite3.Connection:
    dirname = os.path.dirname(db_path)
    if dirname:
        os.makedirs(dirname, mode=0o700, exist_ok=True)

    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row

    try:
        if os.path.exists(db_path):
            os.chmod(db_path, 0o600)
    except OSError:
        pass

    with conn:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.executescript(SCHEMA_SQL)
        migrate_db_severities(conn)

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
    use_lock = lock if lock is not None else _DEFAULT_DB_LOCK
    
    if timestamp is None:
        timestamp = datetime.now(timezone.utc).isoformat()

    if isinstance(details, (dict, list)):
        details_str = json.dumps(details, ensure_ascii=False)
    else:
        details_str = str(details)

    norm_severity = normalize_severity(severity)

    sql = """
    INSERT INTO events (module, event_type, severity, details, timestamp)
    VALUES (?, ?, ?, ?, ?)
    """

    with use_lock:
        cursor = conn.cursor()
        cursor.execute(sql, (module, event_type, norm_severity, details_str, timestamp))
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
    events = query_timeline(conn, lock=lock, module=module, severity=severity)
    
    dir_path = os.path.dirname(os.path.abspath(filepath))
    os.makedirs(dir_path, mode=0o700, exist_ok=True)

    if format_type.lower() == "csv":
        import csv
        with open(filepath, "w", newline="", encoding="utf-8") as csvfile:
            fieldnames = ["id", "timestamp", "module", "event_type", "severity", "details"]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for ev in events:
                writer.writerow({
                    "id": sanitize_csv_cell(ev["id"]),
                    "timestamp": sanitize_csv_cell(ev["timestamp"]),
                    "module": sanitize_csv_cell(ev["module"]),
                    "event_type": sanitize_csv_cell(ev["event_type"]),
                    "severity": sanitize_csv_cell(ev["severity"]),
                    "details": sanitize_csv_cell(ev["raw_details"])
                })
    else:
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(events, f, indent=2, ensure_ascii=False)

    try:
        os.chmod(filepath, 0o600)
    except OSError:
        pass

    return filepath


def get_timeline_stats(
    conn: sqlite3.Connection,
    lock: Optional[threading.Lock] = None
) -> Dict[str, Any]:
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
