"""
core/memory_module.py - Memory Forensics Module (volatility3 wrapper)
Analyzes RAM dumps to extract processes, network sockets, and code injection (malfind).
"""

import json
import os
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

from core.db import log_event
from core.process_runner import run_command


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
    r"-enc\s+[A-Za-z0-9+/=]{20,}",  # Base64 encoded powershell
    r"downloadstring",
    r"iex\s*\(",
    r"invoke-expression",
    r"curl\s+.*\|\s*sh",
    r"wget\s+.*\|\s*sh",
]


def find_volatility_binary() -> Optional[str]:
    """
    Finds the volatility 3 CLI binary path on the system.
    """
    candidates = [
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

    # Fallback to which
    stdout, _, rc = run_command(["which", "vol"])
    if rc == 0 and stdout.strip():
        return stdout.strip()

    stdout, _, rc = run_command(["which", "vol3"])
    if rc == 0 and stdout.strip():
        return stdout.strip()

    return None


def run_volatility_plugin(
    dump_path: str,
    plugin: str,
    timeout: int = 180
) -> Tuple[bool, List[Dict[str, Any]], str]:
    """
    Executes a Volatility 3 plugin against a memory dump using the JSON renderer.
    
    :param dump_path: Path to memory dump (.raw, .vmem, .dmp, etc.)
    :param plugin: Volatility 3 plugin (e.g. 'windows.pslist', 'windows.malfind')
    :return: (success, parsed_rows, error_message)
    """
    dump_path = os.path.abspath(dump_path)
    if not os.path.isfile(dump_path):
        return False, [], f"Memory dump file does not exist: {dump_path}"

    vol_bin = find_volatility_binary()
    if vol_bin:
        cmd = [vol_bin, "-f", dump_path, "-r", "json", plugin]
    else:
        # Fallback to python module execution
        py_bin = sys.executable
        cmd = [py_bin, "-m", "volatility3.cli", "-f", dump_path, "-r", "json", plugin]

    stdout, stderr, rc = run_command(cmd, timeout=timeout)

    if rc != 0 and not stdout:
        return False, [], f"Volatility execution failed (exit code {rc}): {stderr}"

    try:
        data = json.loads(stdout)
        if isinstance(data, list):
            return True, data, ""
        elif isinstance(data, dict):
            # Some versions return dict with results or header
            rows = data.get("rows", [data])
            return True, rows, ""
        return True, [], ""
    except json.JSONDecodeError:
        # In case stdout is json lines
        rows = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
                rows.append(item)
            except Exception:
                pass
        if rows:
            return True, rows, ""
        return False, [], f"Failed to parse Volatility JSON output: {stdout[:500]}"


def parse_sample_forensic_artifact(dump_path: str) -> Optional[Dict[str, Any]]:
    """
    If the file is a synthetic/sample JSON forensic artifact (for tests and portfolio demos),
    loads and returns the structured data directly.
    """
    if dump_path.endswith((".json", ".forensic")):
        try:
            with open(dump_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                if "processes" in data or "malfind" in data:
                    return data
        except Exception:
            pass
    return None


def analyze_dump(
    dump_path: str,
    os_type: str = "windows",
    conn=None,
    lock=None,
    timeout: int = 180
) -> Dict[str, Any]:
    """
    Orchestrates memory forensics:
    1. Running processes (pslist)
    2. Network connections at capture time (netscan / netstat)
    3. Code injection detection (malfind)
    Logs findings to unified SQLite events table.
    """
    dump_path = os.path.abspath(dump_path)
    if not os.path.isfile(dump_path):
        return {
            "success": False,
            "dump_file": dump_path,
            "error": f"Memory dump file not found: {dump_path}",
            "processes": [],
            "connections": [],
            "malfind_hits": [],
            "suspicious_findings": []
        }

    # Check for bundled sample forensic artifact format
    sample_data = parse_sample_forensic_artifact(dump_path)
    if sample_data:
        processes = sample_data.get("processes", [])
        connections = sample_data.get("connections", [])
        malfind_hits = sample_data.get("malfind", [])
    else:
        # Run real Volatility plugins
        is_windows = os_type.lower() == "windows"
        pslist_plugin = "windows.pslist" if is_windows else "linux.pslist"
        netscan_plugin = "windows.netscan" if is_windows else "linux.sockstat"
        malfind_plugin = "windows.malfind" if is_windows else "linux.malfind"

        # 1. PSLIST
        ok_ps, ps_data, err_ps = run_volatility_plugin(dump_path, pslist_plugin, timeout=timeout)
        processes = _normalize_pslist(ps_data)

        # 2. NETSCAN
        ok_net, net_data, err_net = run_volatility_plugin(dump_path, netscan_plugin, timeout=timeout)
        connections = _normalize_netscan(net_data)

        # 3. MALFIND
        ok_mal, mal_data, err_mal = run_volatility_plugin(dump_path, malfind_plugin, timeout=timeout)
        malfind_hits = _normalize_malfind(mal_data)

    # Security Analysis & Anomaly Correlation
    suspicious_findings: List[Dict[str, Any]] = []

    # Check processes
    for p in processes:
        pname = p.get("name", "").lower()
        pid = p.get("pid")
        ppid = p.get("ppid")

        if pname in SUSPICIOUS_PROCESS_NAMES:
            reason = SUSPICIOUS_PROCESS_NAMES[pname]
            suspicious_findings.append({
                "category": "process",
                "severity": "critical" if "mimikatz" in pname or "meterpreter" in pname else "warning",
                "title": f"Suspicious Process '{p.get('name')}' (PID: {pid})",
                "details": f"{reason}. Parent PID: {ppid}."
            })

    # Check malfind injections (all malfind hits are high severity)
    for m in malfind_hits:
        suspicious_findings.append({
            "category": "memory_injection",
            "severity": "critical",
            "title": f"Injected Code Region in {m.get('process_name', 'Process')} (PID: {m.get('pid')})",
            "details": f"Memory page at {m.get('start_address', 'unknown')} with {m.get('protection', 'RWX')} permissions."
        })

    # Check network connections
    for c in connections:
        foreign_port = c.get("foreign_port")
        state = c.get("state", "").upper()
        if foreign_port in (4444, 1337, 8888, 6667) or state == "ESTABLISHED" and foreign_port == 23:
            suspicious_findings.append({
                "category": "network",
                "severity": "warning",
                "title": f"Suspicious Memory Socket to Port {foreign_port}",
                "details": f"PID {c.get('pid')} connected to {c.get('foreign_addr')}:{foreign_port} ({state})"
            })

    # Log to Unified SQLite Database
    if conn is not None:
        log_event(
            conn,
            lock,
            module="memory",
            event_type="dump_analysis_completed",
            severity="info",
            details={
                "dump_file": os.path.basename(dump_path),
                "os_type": os_type,
                "process_count": len(processes),
                "connection_count": len(connections),
                "malfind_hits": len(malfind_hits),
                "suspicious_count": len(suspicious_findings)
            }
        )

        for finding in suspicious_findings:
            log_event(
                conn,
                lock,
                module="memory",
                event_type=f"memory_{finding['category']}",
                severity=finding["severity"],
                details=finding
            )

    return {
        "success": True,
        "dump_file": dump_path,
        "os_type": os_type,
        "process_count": len(processes),
        "connection_count": len(connections),
        "malfind_count": len(malfind_hits),
        "processes": processes,
        "connections": connections,
        "malfind_hits": malfind_hits,
        "suspicious_findings": suspicious_findings
    }


def _normalize_pslist(raw_rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Normalizes Volatility pslist JSON structures."""
    normalized = []
    for r in raw_rows:
        pid = r.get("PID") or r.get("pid") or 0
        ppid = r.get("PPID") or r.get("ppid") or 0
        name = r.get("ImageFileName") or r.get("COMM") or r.get("name") or "unknown"
        create_time = r.get("CreateTime") or r.get("created") or "N/A"
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
    """Normalizes Volatility netscan JSON structures."""
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
    """Normalizes Volatility malfind JSON structures."""
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
