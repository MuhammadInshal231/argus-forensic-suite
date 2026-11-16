"""
core/scan_module.py - Vulnerability & Port Scanner Module (nmap wrapper)
Enforces target authorization guardrails, runs high-performance scans, and parses structured XML into forensic events.
"""

import ipaddress
import re
import socket
import subprocess
import time
import xml.etree.ElementTree as ET
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from core.db import log_event
from core.process_runner import run_command


# Legal and Ethical Allow-list: Private, CGNAT & Local Ranges
ALLOWED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),      # Loopback IPv4
    ipaddress.ip_network("::1/128"),          # Loopback IPv6
    ipaddress.ip_network("10.0.0.0/8"),       # RFC 1918 Private Class A
    ipaddress.ip_network("172.16.0.0/12"),    # RFC 1918 Private Class B
    ipaddress.ip_network("192.168.0.0/16"),   # RFC 1918 Private Class C
    ipaddress.ip_network("100.64.0.0/10"),    # RFC 6598 Shared Address Space / CGNAT
    ipaddress.ip_network("169.254.0.0/16"),   # Link-Local
]

ALLOWED_HOSTNAMES = {"localhost", "localhost.localdomain"}

# Known risky / legacy / insecure ports and services
RISKY_SERVICES_MAP = {
    21: {"service": "ftp", "severity": "warning", "reason": "Plaintext authentication & unencrypted data transfer"},
    23: {"service": "telnet", "severity": "critical", "reason": "Insecure plaintext remote terminal; credential sniffing target"},
    69: {"service": "tftp", "severity": "warning", "reason": "Trivial FTP without authentication"},
    79: {"service": "finger", "severity": "warning", "reason": "Information disclosure / user enumeration service"},
    135: {"service": "msrpc", "severity": "warning", "reason": "Microsoft RPC endpoint mapper; lateral movement vector"},
    139: {"service": "netbios-ssn", "severity": "warning", "reason": "Legacy NetBIOS session service"},
    445: {"service": "microsoft-ds", "severity": "warning", "reason": "SMB service; risk of SMB exploits (EternalBlue) and relay attacks"},
    512: {"service": "rexec", "severity": "critical", "reason": "Legacy unencrypted remote execution daemon"},
    513: {"service": "rlogin", "severity": "critical", "reason": "Legacy unencrypted rlogin daemon"},
    514: {"service": "rsh", "severity": "critical", "reason": "Legacy unencrypted remote shell daemon"},
    1433: {"service": "ms-sql-s", "severity": "warning", "reason": "Database engine port directly exposed"},
    1521: {"service": "oracle", "severity": "warning", "reason": "Oracle TNS listener directly exposed"},
    3306: {"service": "mysql", "severity": "warning", "reason": "MySQL database port directly exposed"},
    3389: {"service": "ms-wbt-server", "severity": "warning", "reason": "Remote Desktop Protocol (RDP) exposed; brute-force/BlueKeep target"},
    5432: {"service": "postgresql", "severity": "warning", "reason": "PostgreSQL database port exposed"},
    5900: {"service": "vnc", "severity": "warning", "reason": "VNC remote desktop exposed without TLS"},
    6379: {"service": "redis", "severity": "critical", "reason": "Redis cache exposed; potential unauthenticated remote code execution"},
    9200: {"service": "elasticsearch", "severity": "warning", "reason": "Elasticsearch API exposed without perimeter control"},
    27017: {"service": "mongodb", "severity": "warning", "reason": "MongoDB database exposed; check for open authentication"},
}


def get_local_host_ips() -> Set[str]:
    """
    Dynamically identifies all IPv4 and IPv6 addresses assigned to local host interfaces.
    """
    ips = {"127.0.0.1", "::1"}

    # 1. Socket connection trick to detect outbound default route IP
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ips.add(s.getsockname()[0])
        s.close()
    except Exception:
        pass

    # 2. Query system hostname getaddrinfo
    try:
        host = socket.gethostname()
        for info in socket.getaddrinfo(host, None):
            ips.add(info[4][0])
    except Exception:
        pass

    # 3. Query system ip addr via command
    try:
        stdout, _, rc = run_command(["ip", "-4", "addr"])
        if rc == 0 and stdout:
            for m in re.finditer(r"inet\s+(\d+\.\d+\.\d+\.\d+)", stdout):
                ips.add(m.group(1))
    except Exception:
        pass

    return ips


def is_target_allowed(target: str, allow_custom: bool = False) -> Tuple[bool, str]:
    """
    Validates target against authorized local/lab networks and dynamic host IPs.
    If allow_custom is True, permits explicit authorized target testing under PECA 2016.
    """
    target = target.strip()
    if not target:
        return False, "Target address cannot be empty."

    # Strip port or URL scheme if user typed it
    if "://" in target:
        target = target.split("://", 1)[1]
    if "/" in target and not target.endswith(("/8", "/10", "/12", "/16", "/24", "/32")):
        target = target.split("/", 1)[0]
    if ":" in target and not target.count(":") > 1:  # IPv4 with port
        target = target.split(":", 1)[0]

    # Check allowed hostnames
    if target.lower() in ALLOWED_HOSTNAMES:
        return True, f"Hostname '{target}' is authorized (Localhost)."

    # Check dynamically detected host IPs
    local_ips = get_local_host_ips()
    if target in local_ips:
        return True, f"Target '{target}' is verified as your own host network interface."

    # Try resolving hostname to IP
    try:
        ip = ipaddress.ip_address(target)
    except ValueError:
        try:
            resolved_ip_str = socket.gethostbyname(target)
            ip = ipaddress.ip_address(resolved_ip_str)
        except Exception as exc:
            return False, f"Could not resolve host '{target}': {exc}"

    # Check if IP falls into any standard lab network (RFC 1918, CGNAT, Loopback)
    for net in ALLOWED_NETWORKS:
        if ip in net:
            return True, f"Target {ip} is within authorized lab network {net}."

    # Check custom user authorization override
    if allow_custom:
        return True, f"Target {ip} authorized under explicit user certification (ACCEPTABLE_USE.md)."

    return False, (
        f"TARGET GUARDRAIL: {ip} is outside default private lab subnets. "
        "Check 'Authorize Custom Target' if you have explicit ownership/written authorization."
    )


def parse_nmap_xml(xml_string: str) -> Tuple[str, List[Dict[str, Any]], Dict[str, Any]]:
    """
    Parses Nmap XML output string into host status, open port details, and extra info.
    
    :param xml_string: XML text returned by 'nmap -oX -'
    :return: (host_status, list_of_open_ports, metadata_dict)
    """
    ports_found: List[Dict[str, Any]] = []
    host_status = "down"
    meta = {
        "hostname": "",
        "ip": "",
        "closed_or_filtered_count": 0,
        "filter_reason": ""
    }

    if not xml_string or "<nmaprun" not in xml_string:
        return host_status, ports_found, meta

    try:
        root = ET.fromstring(xml_string)
    except ET.ParseError:
        return "parse_error", ports_found, meta

    # Check runstats summary and hosts counts
    hosts_elem = root.find(".//hosts")
    if hosts_elem is not None:
        try:
            up_count = int(hosts_elem.attrib.get("up", 0))
            if up_count > 0:
                host_status = "up"
        except Exception:
            pass

    host = root.find("host")
    if host is None:
        if host_status == "up":
            meta["filter_reason"] = "closed/filtered (all scanned ports closed or dropped)"
        return host_status, ports_found, meta

    status_elem = host.find("status")
    if status_elem is not None:
        host_status = status_elem.attrib.get("state", host_status)

    address_elem = host.find("address")
    if address_elem is not None:
        meta["ip"] = address_elem.attrib.get("addr", "")

    hostname_elem = host.find(".//hostname")
    if hostname_elem is not None:
        meta["hostname"] = hostname_elem.attrib.get("name", "")

    ports_parent = host.find("ports")
    if ports_parent is None:
        return host_status, ports_found, meta

    # Check extraports (closed / filtered by firewall)
    extraports_elem = ports_parent.find("extraports")
    if extraports_elem is not None:
        meta["closed_or_filtered_count"] = int(extraports_elem.attrib.get("count", 0))
        meta["filter_reason"] = extraports_elem.attrib.get("state", "")

    for port_elem in ports_parent.findall("port"):
        protocol = port_elem.attrib.get("protocol", "tcp")
        port_id = int(port_elem.attrib.get("portid", 0))

        state_elem = port_elem.find("state")
        state = state_elem.attrib.get("state", "unknown") if state_elem is not None else "unknown"

        if state != "open":
            continue

        service_elem = port_elem.find("service")
        service_name = "unknown"
        product = ""
        version = ""
        extra_info = ""
        cpes = []

        if service_elem is not None:
            service_name = service_elem.attrib.get("name", "unknown")
            product = service_elem.attrib.get("product", "")
            version = service_elem.attrib.get("version", "")
            extra_info = service_elem.attrib.get("extrainfo", "")

            for cpe_elem in service_elem.findall("cpe"):
                if cpe_elem.text:
                    cpes.append(cpe_elem.text.strip())

        full_version = " ".join(filter(None, [product, version, extra_info])).strip()

        # Assess risk level
        risk_meta = RISKY_SERVICES_MAP.get(port_id)
        if risk_meta:
            severity = risk_meta["severity"]
            risk_desc = risk_meta["reason"]
        elif service_name in ("http", "telnet", "ftp"):
            severity = "warning"
            risk_desc = f"Unencrypted service '{service_name}' identified"
        else:
            severity = "info"
            risk_desc = "Standard open service detected"

        ports_found.append({
            "port": port_id,
            "protocol": protocol,
            "state": state,
            "service": service_name,
            "version": full_version or "N/A",
            "cpe": ", ".join(cpes) if cpes else "N/A",
            "severity": severity,
            "risk_description": risk_desc
        })

    return host_status, ports_found, meta


def run_scan(
    target: str,
    scan_type: str = "-sV -T4 --open -Pn",
    conn=None,
    lock=None,
    timeout: int = 120,
    allow_custom: bool = False,
    line_callback: Optional[Callable[[str], None]] = None
) -> Dict[str, Any]:
    """
    Executes a high-performance Nmap scan against an authorized target, parses XML, and logs events.
    """
    start_time = time.time()
    
    # 1. Target Allow-list Guardrail
    allowed, message = is_target_allowed(target, allow_custom=allow_custom)
    if not allowed:
        return {
            "success": False,
            "target": target,
            "error": message,
            "host_status": "blocked",
            "open_ports_count": 0,
            "risky_services_count": 0,
            "ports": [],
            "elapsed_seconds": 0.0,
            "diagnostic_message": message
        }

    # 2. Build High-Performance Nmap Command
    tokens = scan_type.split()
    valid_flags = {
        "-sT", "-sV", "-sS", "-sC", "-F", "-Pn", "-p-", "-T4", "-T3", "-T2",
        "--open", "--top-ports", "-p", "--max-retries"
    }

    cleaned_args = []
    skip_next = False
    for i, tok in enumerate(tokens):
        if skip_next:
            skip_next = False
            continue
        if tok in valid_flags:
            cleaned_args.append(tok)
            if tok in ("--top-ports", "-p", "--max-retries") and i + 1 < len(tokens):
                cleaned_args.append(tokens[i + 1])
                skip_next = True
        elif tok.startswith("-p"):
            cleaned_args.append(tok)

    # Ensure baseline performance optimization flags are present
    if not any(f.startswith("-T") for f in cleaned_args):
        cleaned_args.append("-T4")
    if "-Pn" not in cleaned_args:
        cleaned_args.append("-Pn")  # Treat host as up; bypass dropped ICMP
    if "-sV" in cleaned_args and "--open" not in cleaned_args:
        cleaned_args.append("--open")  # Do not probe version on closed/filtered ports!

    cmd = ["nmap"] + cleaned_args + ["-oX", "-", target]

    if line_callback:
        line_callback(f"[*] Running command: {' '.join(cmd)}")

    stdout, stderr, rc = run_command(cmd, timeout=timeout)
    elapsed = round(time.time() - start_time, 2)

    if rc != 0 and not stdout:
        err_msg = f"Nmap execution failed (code {rc}): {stderr}"
        if line_callback:
            line_callback(f"[ERROR] {err_msg}")
        return {
            "success": False,
            "target": target,
            "error": err_msg,
            "host_status": "error",
            "open_ports_count": 0,
            "risky_services_count": 0,
            "ports": [],
            "elapsed_seconds": elapsed,
            "diagnostic_message": err_msg
        }

    # 3. Parse XML
    host_status, ports, meta = parse_nmap_xml(stdout)
    risky_count = sum(1 for p in ports if p["severity"] in ("warning", "critical"))

    # Build human-friendly diagnostic feedback
    if host_status == "up" and len(ports) == 0:
        diag_msg = (
            f"Host {target} is UP, but all {meta.get('closed_or_filtered_count', 'scanned')} ports "
            f"are in {meta.get('filter_reason', 'closed/filtered')} state. "
            "No active listening network services were found on the scanned ports."
        )
    elif host_status == "up":
        diag_msg = f"Host {target} is UP. Discovered {len(ports)} open port(s) with {risky_count} flagged as risky."
    else:
        diag_msg = f"Host {target} appears to be {host_status}."

    if line_callback:
        line_callback(f"[+] {diag_msg}")

    # 4. Log Events to Unified DB
    if conn is not None:
        log_event(
            conn,
            lock,
            module="scan",
            event_type="host_scan_completed",
            severity="info" if host_status == "up" else "warning",
            details={
                "target": target,
                "host_status": host_status,
                "open_ports": len(ports),
                "risky_services": risky_count,
                "scan_type": " ".join(cleaned_args),
                "elapsed": elapsed,
                "diagnostic": diag_msg
            }
        )

        for p in ports:
            log_event(
                conn,
                lock,
                module="scan",
                event_type="open_port",
                severity=p["severity"],
                details={
                    "target": target,
                    "port": p["port"],
                    "protocol": p["protocol"],
                    "service": p["service"],
                    "version": p["version"],
                    "risk_assessment": p["risk_description"]
                }
            )

    return {
        "success": True,
        "target": target,
        "host_status": host_status,
        "scan_args": " ".join(cleaned_args),
        "open_ports_count": len(ports),
        "risky_services_count": risky_count,
        "ports": ports,
        "elapsed_seconds": elapsed,
        "diagnostic_message": diag_msg,
        "meta": meta,
        "raw_xml": stdout[:5000]
    }
