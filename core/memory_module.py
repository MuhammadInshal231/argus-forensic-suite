"""
core/memory_module.py - Memory Forensics Module (volatility3 wrapper)
Analyzes RAM dumps to extract processes, network sockets, and code injection (malfind).
"""

from datetime import datetime, timezone
import hashlib
import json
import os
import re
import stat
import sys
from typing import Any, Dict, List, Optional, Set, Tuple

from core.db import log_event
from core.process_runner import run_command


def validate_and_hash_dump(dump_path: str) -> Tuple[bool, str, str, str, int]:
    try:
        real_path = os.path.realpath(dump_path)
    except Exception as exc:
        return False, f"Invalid file path: {exc}", "", "", 0

    if not os.path.exists(real_path):
        return False, f"File does not exist: {real_path}", "", "", 0

    try:
        st = os.stat(real_path)
        if not stat.S_ISREG(st.st_mode):
            return False, f"Target is not a regular file: {real_path}", "", "", 0
    except Exception as exc:
        return False, f"Could not inspect file attributes: {exc}", "", "", 0

    if not os.access(real_path, os.R_OK):
        return False, f"Permission denied: cannot read {real_path}", "", "", 0

    try:
        hasher = hashlib.sha256()
        with open(real_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                hasher.update(chunk)
        digest = hasher.hexdigest()
        return True, "", real_path, digest, st.st_size
    except Exception as exc:
        return False, f"Error hashing memory image: {exc}", "", "", 0


SUSPICIOUS_PROCESS_NAMES = {
    "mimikatz.exe": "Known credential dumping utility",
    "nc.exe": "Netcat reverse shell binary",
    "ncat.exe": "Netcat utility binary",
    "meterpreter.exe": "Metasploit payload",
    "svch0st.exe": "Typosquatting disguise of legitimate svchost",
    "lsasss.exe": "Typosquatting disguise of legitimate lsass",
    "powershell_ise.exe": "Interactive PowerShell scripting engine",
    "cmd.exe": "Command prompt execution",
}

SUSPICIOUS_COMMAND_PATTERNS = [
    r"-enc\s+[A-Za-z0-9+/=]{20,}",
    r"downloadstring",
    r"iex\s*\(",
    r"invoke-expression",
    r"curl\s+.*\|\s*sh",
    r"wget\s+.*\|\s*sh",
]

WINDOWS_PLUGINS = [
    "windows.pslist",
    "windows.pstree",
    "windows.psscan",
    "windows.cmdline",
    "windows.netscan",
    "windows.malfind",
]

LINUX_PLUGINS = [
    "linux.pslist",
    "linux.pstree",
    "linux.psscan",
    "linux.sockstat",
    "linux.malfind",
    "linux.bash",
]


def find_volatility_binary() -> Optional[str]:
    candidates = [
        os.path.join(os.path.dirname(sys.executable), "vol"),
        os.path.join(os.path.dirname(sys.executable), "vol3"),
        os.path.abspath(".venv/bin/vol"),
        os.path.abspath(".venv/bin/vol3"),
        "/usr/local/bin/vol",
        "/usr/local/bin/vol3",
        "/usr/bin/vol",
        "/usr/bin/vol3",
    ]
    for c in candidates:
        if os.path.isfile(c) and os.access(c, os.X_OK):
            return c

    stdout, _, rc = run_command(["which", "vol"])
    if rc == 0 and stdout.strip():
        return stdout.strip()

    stdout, _, rc = run_command(["which", "vol3"])
    if rc == 0 and stdout.strip():
        return stdout.strip()

    try:
        import volatility3
        return sys.executable
    except ImportError:
        pass

    return None


def format_volatility_error(stdout: str, stderr: str) -> str:
    combined = f"{stdout}\n{stderr}".strip()
    if "Symbol table not found" in combined or "symbol table" in combined.lower() or "unsatisfied requirement" in combined.lower():
        if "linux" in combined.lower():
            return "Linux symbol table missing: Volatility 3 requires a matching kernel symbol table (ISF JSON) for Linux memory analysis. Symbol file not found in Volatility symbols directory."
        return "Symbol table missing: Volatility 3 could not resolve required symbols or kernel profile for this memory image."
    if "No suitable layer could be loaded" in combined or "layer_name" in combined:
        return "Unsupported memory format: Volatility 3 could not identify a valid address space layer. Ensure image is acquired cleanly (.raw/.vmem/.dmp)."
    if "timed out" in combined.lower():
        return "Volatility plugin analysis timed out."
    first_lines = [line.strip() for line in combined.splitlines() if line.strip() and not line.startswith("Volatility 3 Framework")]
    if first_lines:
        return f"Volatility diagnostic: {first_lines[0][:300]}"
    return "Volatility plugin execution failed with unknown error."


def detect_os(dump_path: str) -> str:
    real_path = os.path.realpath(dump_path)
    sample_data = parse_sample_forensic_artifact(real_path)
    if sample_data:
        return str(sample_data.get("os_type", "windows")).lower()

    try:
        with open(real_path, "rb") as f:
            header = f.read(16384)
            if b"PAGEDUMP" in header or b"PAGEHASH" in header or b"MDMP" in header or b"Microsoft" in header:
                return "windows"
            if b"\x7fELF" in header or b"Linux version" in header:
                return "linux"
    except Exception:
        pass

    ok_win, win_rows, _ = run_volatility_plugin(real_path, "windows.info", timeout=20)
    if ok_win and win_rows:
        return "windows"

    return "windows"


def run_volatility_plugin(
    dump_path: str,
    plugin: str,
    timeout: int = 180
) -> Tuple[bool, List[Dict[str, Any]], str]:
    dump_path = os.path.abspath(dump_path)
    if not os.path.isfile(dump_path):
        return False, [], f"Memory dump file does not exist: {dump_path}"

    vol_bin = find_volatility_binary()
    if vol_bin and vol_bin != sys.executable:
        cmd = [vol_bin, "-f", dump_path, "-r", "json", plugin]
    else:
        cmd = [sys.executable, "-m", "volatility3.cli", "-f", dump_path, "-r", "json", plugin]

    stdout, stderr, rc = run_command(cmd, timeout=timeout)

    if rc != 0 and not stdout:
        clean_err = format_volatility_error(stdout, stderr)
        return False, [], clean_err

    json_candidate = stdout
    start_bracket = stdout.find("[")
    start_brace = stdout.find("{")
    valid_starts = [idx for idx in [start_bracket, start_brace] if idx != -1]
    
    if valid_starts:
        start_idx = min(valid_starts)
        end_idx = max(stdout.rfind("]"), stdout.rfind("}"))
        if end_idx > start_idx:
            json_candidate = stdout[start_idx:end_idx + 1]

    try:
        data = json.loads(json_candidate)
        if isinstance(data, list):
            return True, data, ""
        elif isinstance(data, dict):
            rows = data.get("rows", [data])
            return True, rows, ""
        return True, [], ""
    except json.JSONDecodeError:
        rows = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line or not (line.startswith("{") and line.endswith("}")):
                continue
            try:
                item = json.loads(line)
                rows.append(item)
            except Exception:
                pass
        if rows:
            return True, rows, ""
        
        clean_err = format_volatility_error(stdout, stderr)
        return False, [], clean_err


def parse_sample_forensic_artifact(dump_path: str) -> Optional[Dict[str, Any]]:
    if dump_path.endswith((".json", ".forensic")):
        try:
            with open(dump_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                if "processes" in data or "malfind" in data or "connections" in data:
                    return data
        except Exception:
            pass
    return None


def normalize_iso_utc(ts_str: Optional[str]) -> str:
    if not ts_str or str(ts_str).strip() in ("N/A", "None", ""):
        return datetime.now(timezone.utc).isoformat()
    s = str(ts_str).strip()
    try:
        if s.endswith("Z"):
            s_core = s[:-1]
            dt = datetime.fromisoformat(s_core).replace(tzinfo=timezone.utc)
            return dt.isoformat()
        if " " in s and "T" not in s:
            s_iso = s.replace(" ", "T")
            dt = datetime.fromisoformat(s_iso)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.isoformat()
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat()
    except Exception:
        return datetime.now(timezone.utc).isoformat()


def analyze_dump(
    dump_path: str,
    os_type: str = "auto",
    conn=None,
    lock=None,
    timeout: int = 180
) -> Dict[str, Any]:
    valid, err_msg, real_path, sha256_hash, file_size = validate_and_hash_dump(dump_path)
    if not valid:
        return {
            "success": False,
            "dump_file": dump_path,
            "error": err_msg,
            "sha256": "",
            "file_size": 0,
            "os_type": os_type,
            "processes": [],
            "connections": [],
            "malfind_hits": [],
            "hidden_processes": [],
            "suspicious_findings": []
        }

    resolved_os = os_type.lower()
    if resolved_os == "auto":
        resolved_os = detect_os(real_path)

    sample_data = parse_sample_forensic_artifact(real_path)
    processes: List[Dict[str, Any]] = []
    connections: List[Dict[str, Any]] = []
    malfind_hits: List[Dict[str, Any]] = []
    psscan_processes: List[Dict[str, Any]] = []

    if sample_data:
        processes = sample_data.get("processes", [])
        connections = sample_data.get("connections", [])
        malfind_hits = sample_data.get("malfind", [])
        psscan_processes = sample_data.get("psscan", [])
    else:
        if resolved_os == "windows":
            if os_type.lower() == "linux":
                return {
                    "success": False,
                    "dump_file": real_path,
                    "error": "OS mismatch: Cannot run Linux plugins on a Windows memory dump.",
                    "sha256": sha256_hash,
                    "file_size": file_size,
                    "os_type": resolved_os,
                    "processes": [],
                    "connections": [],
                    "malfind_hits": [],
                    "hidden_processes": [],
                    "suspicious_findings": []
                }
            ok_ps, ps_data, err_ps = run_volatility_plugin(dump_path, "windows.pslist", timeout=timeout)
            if not ok_ps and err_ps:
                return {
                    "success": False,
                    "dump_file": real_path,
                    "error": err_ps,
                    "sha256": sha256_hash,
                    "file_size": file_size,
                    "os_type": resolved_os,
                    "processes": [],
                    "connections": [],
                    "malfind_hits": [],
                    "hidden_processes": [],
                    "suspicious_findings": []
                }
            processes = _normalize_pslist(ps_data)

            ok_scan, scan_data, _ = run_volatility_plugin(dump_path, "windows.psscan", timeout=timeout)
            if ok_scan:
                psscan_processes = _normalize_pslist(scan_data)

            ok_net, net_data, _ = run_volatility_plugin(dump_path, "windows.netscan", timeout=timeout)
            if ok_net:
                connections = _normalize_netscan(net_data)

            ok_mal, mal_data, _ = run_volatility_plugin(dump_path, "windows.malfind", timeout=timeout)
            if ok_mal:
                malfind_hits = _normalize_malfind(mal_data)
        else:
            if os_type.lower() == "windows":
                return {
                    "success": False,
                    "dump_file": real_path,
                    "error": "OS mismatch: Cannot run Windows plugins on a Linux memory dump.",
                    "sha256": sha256_hash,
                    "file_size": file_size,
                    "os_type": resolved_os,
                    "processes": [],
                    "connections": [],
                    "malfind_hits": [],
                    "hidden_processes": [],
                    "suspicious_findings": []
                }
            ok_ps, ps_data, err_ps = run_volatility_plugin(dump_path, "linux.pslist", timeout=timeout)
            if not ok_ps:
                return {
                    "success": False,
                    "dump_file": real_path,
                    "error": err_ps,
                    "sha256": sha256_hash,
                    "file_size": file_size,
                    "os_type": resolved_os,
                    "processes": [],
                    "connections": [],
                    "malfind_hits": [],
                    "hidden_processes": [],
                    "suspicious_findings": []
                }
            processes = _normalize_pslist(ps_data)

            ok_scan, scan_data, _ = run_volatility_plugin(dump_path, "linux.psscan", timeout=timeout)
            if ok_scan:
                psscan_processes = _normalize_pslist(scan_data)

            ok_sock, sock_data, _ = run_volatility_plugin(dump_path, "linux.sockstat", timeout=timeout)
            if ok_sock:
                connections = _normalize_netscan(sock_data)

            ok_mal, mal_data, _ = run_volatility_plugin(dump_path, "linux.malfind", timeout=timeout)
            if ok_mal:
                malfind_hits = _normalize_malfind(mal_data)

    suspicious_findings: List[Dict[str, Any]] = []

    active_pids: Set[int] = {int(p["pid"]) for p in processes if "pid" in p and str(p["pid"]).isdigit()}
    hidden_processes: List[Dict[str, Any]] = []
    if psscan_processes:
        for scan_p in psscan_processes:
            scan_pid = scan_p.get("pid")
            if scan_pid and str(scan_pid).isdigit() and int(scan_pid) not in active_pids:
                hidden_processes.append(scan_p)
                proc_time = normalize_iso_utc(scan_p.get("create_time"))
                suspicious_findings.append({
                    "category": "hidden_process",
                    "severity": "medium",
                    "title": f"Possible hidden or terminated process '{scan_p.get('name')}' (PID: {scan_pid})",
                    "details": f"Process '{scan_p.get('name')}' (PID: {scan_pid}) was detected via kernel pool scanning (psscan) but is absent from the active process double-linked list (pslist); requires review.",
                    "timestamp": proc_time
                })

    for p in processes:
        pname = p.get("name", "").lower()
        pid = p.get("pid")
        ppid = p.get("ppid")
        proc_time = normalize_iso_utc(p.get("create_time"))

        if pname in SUSPICIOUS_PROCESS_NAMES:
            reason = SUSPICIOUS_PROCESS_NAMES[pname]
            is_critical = "mimikatz" in pname or "meterpreter" in pname
            suspicious_findings.append({
                "category": "process",
                "severity": "critical" if is_critical else "medium",
                "title": f"Possible suspicious process '{p.get('name')}' (PID: {pid})",
                "details": f"{reason}; parent PID: {ppid}; requires review.",
                "timestamp": proc_time
            })

    for m in malfind_hits:
        suspicious_findings.append({
            "category": "memory_injection",
            "severity": "critical",
            "title": f"Possible injected code region in {m.get('process_name', 'Process')} (PID: {m.get('pid')})",
            "details": f"Memory page at {m.get('start_address', 'unknown')} with {m.get('protection', 'RWX')} permissions; requires review.",
            "timestamp": normalize_iso_utc(None)
        })

    for c in connections:
        foreign_port = c.get("foreign_port")
        state = c.get("state", "").upper()
        if foreign_port in (4444, 1337, 8888, 6667) or (state == "ESTABLISHED" and foreign_port == 23):
            suspicious_findings.append({
                "category": "network",
                "severity": "high" if foreign_port in (4444, 1337) else "medium",
                "title": f"Unusual memory socket to port {foreign_port}",
                "details": f"PID {c.get('pid')} connected to {c.get('foreign_addr')}:{foreign_port} ({state}); requires review.",
                "timestamp": normalize_iso_utc(None)
            })

    if conn is not None:
        log_event(
            conn,
            lock,
            module="memory",
            event_type="dump_analysis_completed",
            severity="info",
            details={
                "dump_file": os.path.basename(real_path),
                "sha256": sha256_hash,
                "file_size": file_size,
                "os_type": resolved_os,
                "process_count": len(processes),
                "connection_count": len(connections),
                "malfind_hits": len(malfind_hits),
                "hidden_processes_count": len(hidden_processes),
                "suspicious_count": len(suspicious_findings)
            }
        )

        for finding in suspicious_findings:
            event_ts = finding.get("timestamp") or normalize_iso_utc(None)
            log_event(
                conn,
                lock,
                module="memory",
                event_type=f"memory_{finding['category']}",
                severity=finding["severity"],
                details=finding,
                timestamp=event_ts
            )

    return {
        "success": True,
        "dump_file": real_path,
        "sha256": sha256_hash,
        "file_size": file_size,
        "os_type": resolved_os,
        "process_count": len(processes),
        "connection_count": len(connections),
        "malfind_count": len(malfind_hits),
        "hidden_process_count": len(hidden_processes),
        "processes": processes,
        "connections": connections,
        "malfind_hits": malfind_hits,
        "hidden_processes": hidden_processes,
        "suspicious_findings": suspicious_findings
    }


def _normalize_pslist(raw_rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    normalized = []
    for r in raw_rows:
        pid = r.get("PID") or r.get("pid") or 0
        ppid = r.get("PPID") or r.get("ppid") or 0
        name = r.get("ImageFileName") or r.get("COMM") or r.get("name") or "unknown"
        create_time = r.get("CreateTime") or r.get("created") or r.get("Start Time") or "N/A"
        threads = r.get("Threads") or r.get("threads") or 0
        normalized.append({
            "pid": int(pid) if str(pid).isdigit() else pid,
            "ppid": int(ppid) if str(ppid).isdigit() else ppid,
            "name": str(name),
            "create_time": str(create_time),
            "threads": int(threads) if str(threads).isdigit() else threads
        })
    return normalized


def _normalize_netscan(raw_rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    normalized = []
    for r in raw_rows:
        proto = r.get("Proto") or r.get("proto") or "TCP"
        loc_addr = r.get("LocalAddr") or r.get("local_addr") or "0.0.0.0"
        loc_port = r.get("LocalPort") or r.get("local_port") or 0
        for_addr = r.get("ForeignAddr") or r.get("foreign_addr") or "0.0.0.0"
        for_port = r.get("ForeignPort") or r.get("foreign_port") or 0
        state = r.get("State") or r.get("state") or "N/A"
        pid = r.get("PID") or r.get("pid") or 0
        owner = r.get("Owner") or r.get("owner") or "unknown"

        normalized.append({
            "proto": str(proto),
            "local_addr": str(loc_addr),
            "local_port": int(loc_port) if str(loc_port).isdigit() else loc_port,
            "foreign_addr": str(for_addr),
            "foreign_port": int(for_port) if str(for_port).isdigit() else for_port,
            "state": str(state),
            "pid": int(pid) if str(pid).isdigit() else pid,
            "owner": str(owner)
        })
    return normalized


def _normalize_malfind(raw_rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    normalized = []
    for r in raw_rows:
        pid = r.get("PID") or r.get("pid") or 0
        pname = r.get("Process") or r.get("process_name") or "unknown"
        start_addr = r.get("Start VPN") or r.get("start_address") or "0x0"
        end_addr = r.get("End VPN") or r.get("end_address") or "0x0"
        protection = r.get("Protection") or r.get("protection") or "PAGE_EXECUTE_READWRITE"
        disasm = r.get("Disassembly") or r.get("disasm") or "N/A"
        hex_dump = r.get("HexDump") or r.get("hexdump") or "N/A"

        normalized.append({
            "pid": int(pid) if str(pid).isdigit() else pid,
            "process_name": str(pname),
            "start_address": str(start_addr),
            "end_address": str(end_addr),
            "protection": str(protection),
            "disassembly": str(disasm),
            "hexdump": str(hex_dump)
        })
    return normalized
