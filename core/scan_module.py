"""
core/scan_module.py - Vulnerability & Port Scanner Module (nmap wrapper)
Enforces strict target allow-listing and parses structured XML into forensic events.
"""

import ipaddress
import socket
import time
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, Tuple

from core.db import log_event
from core.process_runner import run_command


# Legal and Ethical Allow-list: Private & Local Ranges Only
ALLOWED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),      # Loopback IPv4
    ipaddress.ip_network("::1/128"),          # Loopback IPv6
    ipaddress.ip_network("10.0.0.0/8"),       # RFC 1918 Private Class A
    ipaddress.ip_network("172.16.0.0/12"),    # RFC 1918 Private Class B
    ipaddress.ip_network("192.168.0.0/16"),   # RFC 1918 Private Class C
    ipaddress.ip_network("169.254.0.0/16"),   # Link-Local
]

ALLOWED_HOSTNAMES = {"localhost", "localhost.localdomain"}

# Known risky / legacy / insecure ports and services
RISKY_SERVICES_MAP = {
    21: {"service": "ftp", "severity": "warning", "reason": "Plaintext authentication & unencrypted data transfer"},
    23: {"service": "telnet", "severity": "critical", "reason": "Insecure plaintext remote terminal; vulnerable to credential sniffing"},
    69: {"service": "tftp", "severity": "warning", "reason": "Trivial FTP without authentication"},
    79: {"service": "finger", "severity": "warning", "reason": "Information disclosure / user enumeration service"},
    135: {"service": "msrpc", "severity": "warning", "reason": "Microsoft RPC endpoint mapper; target for lateral movement"},
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


def is_target_allowed(target: str) -> Tuple[bool, str]:
    """
    Validates target against authorized local/lab networks.
    Rejects external internet IP addresses and non-local hostnames.
    """
    target = target.strip()
    if not target:
        return False, "Target address cannot be empty."

    # Strip port or URL scheme if user typed it
    if "://" in target:
        target = target.split("://", 1)[1]
    if "/" in target and not target.endswith(("/8", "/12", "/16", "/24", "/32")):
        target = target.split("/", 1)[0]
    if ":" in target and not target.count(":") > 1: # not IPv6
        target = target.split(":", 1)[0]

    # Check allowed hostnames
    if target.lower() in ALLOWED_HOSTNAMES:
        return True, f"Hostname '{target}' is authorized (Localhost)."

    # Try resolving hostname to IP
    try:
        ip = ipaddress.ip_address(target)
    except ValueError:
        try:
            resolved_ip_str = socket.gethostbyname(target)
            ip = ipaddress.ip_address(resolved_ip_str)
        except Exception as exc:
            return False, f"Could not resolve host '{target}': {exc}"

    # Check if IP falls into any allowed lab network
    for net in ALLOWED_NETWORKS:
        if ip in net:
            return True, f"Target {ip} is within authorized lab network {net}."

    return False, (
        f"TARGET REJECTED: {ip} is outside authorized lab ranges "
        "(Only RFC 1918 private subnets and localhost are permitted per ACCEPTABLE_USE.md)."
    )


def parse_nmap_xml(xml_string: str) -> Tuple[str, List[Dict[str, Any]]]:
    """
    Parses Nmap XML output string into host status and open port details.
    
    :param xml_string: XML text returned by 'nmap -oX -'
    :return: (host_status, list_of_ports)
    """
    ports_found: List[Dict[str, Any]] = []
    host_status = "down"

    if not xml_string or "<nmaprun" not in xml_string:
        return host_status, ports_found

    try:
        root = ET.fromstring(xml_string)
    except ET.ParseError:
        return "parse_error", ports_found

    host = root.find("host")
    if host is None:
        return "no_hosts_found", ports_found

    status_elem = host.find("status")
    if status_elem is not None:
        host_status = status_elem.attrib.get("state", "unknown")

    ports_parent = host.find("ports")
    if ports_parent is None:
        return host_status, ports_found

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

    return host_status, ports_found


def run_scan(
    target: str,
    scan_type: str = "-sV",
    conn=None,
    lock=None,
    timeout: int = 180
) -> Dict[str, Any]:
    """
    Executes an Nmap scan against an authorized target, parses XML, and logs events.
    """
    start_time = time.time()
    
    # 1. Target Allow-list Guardrail
    allowed, message = is_target_allowed(target)
    if not allowed:
        return {
            "success": False,
            "target": target,
            "error": message,
            "host_status": "blocked",
            "open_ports_count": 0,
            "risky_services_count": 0,
            "ports": [],
            "elapsed_seconds": 0.0
        }

    # 2. Build Nmap command
    # Allowed scan type options: -sT (connect), -sV (version detection), -sS (syn), -F (fast)
    valid_flags = ["-sT", "-sV", "-sS", "-sC", "-F", "-Pn", "-p-", "-T4"]
    args = [arg for arg in scan_type.split() if arg in valid_flags]
    if not args:
        args = ["-sV"]

    # Always output XML to stdout
    cmd = ["nmap"] + args + ["-oX", "-", target]

    stdout, stderr, rc = run_command(cmd, timeout=timeout)
    elapsed = round(time.time() - start_time, 2)

    if rc != 0 and not stdout:
        return {
            "success": False,
            "target": target,
            "error": f"Nmap execution failed (code {rc}): {stderr}",
            "host_status": "error",
            "open_ports_count": 0,
            "risky_services_count": 0,
            "ports": [],
            "elapsed_seconds": elapsed
        }

    # 3. Parse XML
    host_status, ports = parse_nmap_xml(stdout)
    risky_count = sum(1 for p in ports if p["severity"] in ("warning", "critical"))

    # 4. Log Events to Unified DB
    if conn is not None:
        # Log host discovery event
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
                "scan_type": " ".join(args),
                "elapsed": elapsed
            }
        )

        # Log individual open ports, prioritizing warnings/criticals
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
        "scan_args": " ".join(args),
        "open_ports_count": len(ports),
        "risky_services_count": risky_count,
        "ports": ports,
        "elapsed_seconds": elapsed,
        "raw_xml": stdout[:5000]  # truncate for preview
    }
