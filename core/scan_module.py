"""
core/scan_module.py - Vulnerability & Port Scanner Module (nmap wrapper)
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


ALLOWED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("169.254.0.0/16"),
]

ALLOWED_HOSTNAMES = {"localhost", "localhost.localdomain"}

RISKY_SERVICES_MAP = {
    21: {"service": "ftp", "severity": "medium", "reason": "Possible unencrypted file transfer and authentication; requires review"},
    23: {"service": "telnet", "severity": "critical", "reason": "Possible unencrypted remote terminal session; requires review"},
    69: {"service": "tftp", "severity": "medium", "reason": "Possible unauthenticated TFTP service; requires review"},
    79: {"service": "finger", "severity": "low", "reason": "Possible user enumeration service active; requires review"},
    135: {"service": "msrpc", "severity": "medium", "reason": "Possible Microsoft RPC endpoint exposed; requires review"},
    139: {"service": "netbios-ssn", "severity": "medium", "reason": "Possible NetBIOS session service active; requires review"},
    445: {"service": "microsoft-ds", "severity": "medium", "reason": "Possible SMB service exposed; requires review for SMB signing and access controls"},
    512: {"service": "rexec", "severity": "high", "reason": "Possible legacy unencrypted remote execution daemon; requires review"},
    513: {"service": "rlogin", "severity": "high", "reason": "Possible legacy unencrypted rlogin daemon; requires review"},
    514: {"service": "rsh", "severity": "high", "reason": "Possible legacy unencrypted remote shell daemon; requires review"},
    1433: {"service": "ms-sql-s", "severity": "medium", "reason": "Database engine port directly accessible; requires review"},
    1521: {"service": "oracle", "severity": "medium", "reason": "Oracle TNS listener directly accessible; requires review"},
    3306: {"service": "mysql", "severity": "medium", "reason": "MySQL database port directly accessible; requires review"},
    3389: {"service": "ms-wbt-server", "severity": "medium", "reason": "Remote Desktop Protocol (RDP) exposed; requires review for authentication policy"},
    5432: {"service": "postgresql", "severity": "medium", "reason": "PostgreSQL database port directly accessible; requires review"},
    5900: {"service": "vnc", "severity": "medium", "reason": "VNC remote framebuffer exposed; requires review for transport encryption"},
    6379: {"service": "redis", "severity": "high", "reason": "Possible unauthenticated Redis cache instance; requires review"},
    9200: {"service": "elasticsearch", "severity": "medium", "reason": "Elasticsearch REST interface exposed; requires review"},
    27017: {"service": "mongodb", "severity": "medium", "reason": "MongoDB database interface exposed; requires review"},
}


def get_local_host_ips() -> Set[str]:
    ips = {"127.0.0.1", "::1"}

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ips.add(s.getsockname()[0])
        s.close()
    except Exception:
        pass

    try:
        host = socket.gethostname()
        for info in socket.getaddrinfo(host, None):
            ips.add(info[4][0])
    except Exception:
        pass

    try:
        stdout, _, rc = run_command(["ip", "-4", "addr"])
        if rc == 0 and stdout:
            for m in re.finditer(r"inet\s+(\d+\.\d+\.\d+\.\d+)", stdout):
                ips.add(m.group(1))
    except Exception:
        pass

    return ips


def normalize_target_address(target_str: str) -> Optional[Any]:
    t = target_str.strip()
    if not t:
        return None

    if "/" in t:
        try:
            return ipaddress.ip_network(t, strict=False)
        except ValueError:
            return None

    try:
        ip = ipaddress.ip_address(t)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        return ip
    except ValueError:
        pass

    try:
        raw_bytes = socket.inet_aton(t)
        return ipaddress.IPv4Address(raw_bytes)
    except (OSError, ValueError):
        pass

    try:
        val = int(t, 0)
        return ipaddress.IPv4Address(val)
    except (ValueError, OverflowError):
        pass

    return None


def is_target_allowed(target: str, allow_custom: bool = False) -> Tuple[bool, str, Optional[str]]:
    target = target.strip()
    if not target:
        return False, "Target address cannot be empty.", None

    if target.startswith("-"):
        return False, "Invalid target: target cannot begin with a dash.", None

    if len(target) > 255:
        return False, "Invalid target: target string is excessively long.", None

    if "://" in target:
        target = target.split("://", 1)[1]

    if ":" in target and not target.count(":") > 1:
        target = target.split(":", 1)[0]

    normalized = normalize_target_address(target)

    if isinstance(normalized, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
        prefix_limit = 24 if isinstance(normalized, ipaddress.IPv4Network) else 112
        if normalized.prefixlen < prefix_limit and not allow_custom:
            return (
                False,
                f"Target CIDR range /{normalized.prefixlen} is too large (exceeds /{prefix_limit} limit). Check authorization override to scan.",
                None
            )

        for allowed_net in ALLOWED_NETWORKS:
            try:
                if normalized.subnet_of(allowed_net):
                    return True, f"Target network {normalized} is authorized.", str(normalized)
            except TypeError:
                continue

        if allow_custom:
            return True, f"Target network {normalized} authorized under user override.", str(normalized)

        return False, f"Target range {normalized} straddles unauthorized or external addresses.", None

    if isinstance(normalized, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        ip = normalized
        local_ips = get_local_host_ips()
        if str(ip) in local_ips:
            return True, f"Target {ip} is verified as local host interface.", str(ip)

        for net in ALLOWED_NETWORKS:
            if ip in net:
                return True, f"Target {ip} is within authorized lab network {net}.", str(ip)

        if allow_custom:
            return True, f"Target {ip} authorized under user override.", str(ip)

        return False, f"Target {ip} is outside authorized lab ranges.", None

    resolved_ips: List[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    try:
        addr_infos = socket.getaddrinfo(target, None)
        for item in addr_infos:
            ip_str = item[4][0]
            resolved_ips.append(ipaddress.ip_address(ip_str))
    except Exception as exc:
        return False, f"Could not resolve host '{target}': {exc}", None

    if not resolved_ips:
        return False, f"Could not resolve target hostname '{target}'.", None

    local_ips = get_local_host_ips()
    all_allowed = True
    for rip in resolved_ips:
        in_local = str(rip) in local_ips
        in_allowed_net = any(rip in net for net in ALLOWED_NETWORKS)
        if not (in_local or in_allowed_net):
            all_allowed = False
            break

    primary_ip = str(resolved_ips[0])

    if all_allowed or target.lower() in ALLOWED_HOSTNAMES:
        return True, f"Target '{target}' resolved to authorized IP {primary_ip}.", primary_ip

    if allow_custom:
        return True, f"Target '{target}' ({primary_ip}) authorized under user override.", primary_ip

    return False, f"Target '{target}' resolved to unauthorized external IP {primary_ip}.", None


def parse_nmap_xml(xml_string: str) -> Tuple[str, List[Dict[str, Any]], Dict[str, Any]]:
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

        risk_meta = RISKY_SERVICES_MAP.get(port_id)
        if risk_meta:
            severity = risk_meta["severity"]
            risk_desc = risk_meta["reason"]
        elif service_name in ("http", "telnet", "ftp"):
            severity = "medium"
            risk_desc = f"Possible unencrypted service '{service_name}' identified; requires review"
        else:
            severity = "info"
            risk_desc = "Standard open service identified; routine finding"

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
    start_time = time.time()
    
    allowed, message, resolved_target = is_target_allowed(target, allow_custom=allow_custom)
    if not allowed or not resolved_target:
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

    if allow_custom and conn is not None:
        log_event(
            conn,
            lock,
            module="scan",
            event_type="target_override_authorized",
            severity="warning",
            details={
                "target_input": target,
                "resolved_target": resolved_target,
                "policy": "User certified explicit authorization per ACCEPTABLE_USE.md"
            }
        )

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

    if not any(f.startswith("-T") for f in cleaned_args):
        cleaned_args.append("-T4")
    if "-Pn" not in cleaned_args:
        cleaned_args.append("-Pn")
    if "-sV" in cleaned_args and "--open" not in cleaned_args:
        cleaned_args.append("--open")

    cmd = ["nmap"] + cleaned_args + ["-oX", "-", "--", resolved_target]

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
            "resolved_target": resolved_target,
            "error": err_msg,
            "host_status": "error",
            "open_ports_count": 0,
            "risky_services_count": 0,
            "ports": [],
            "elapsed_seconds": elapsed,
            "diagnostic_message": err_msg
        }

    host_status, ports, meta = parse_nmap_xml(stdout)
    risky_count = sum(1 for p in ports if p["severity"] in ("low", "medium", "high", "critical"))

    if host_status == "up" and len(ports) == 0:
        diag_msg = (
            f"Host {resolved_target} is UP, but all {meta.get('closed_or_filtered_count', 'scanned')} ports "
            f"are in {meta.get('filter_reason', 'closed/filtered')} state. "
            "No active listening network services were found on the scanned ports."
        )
    elif host_status == "up":
        diag_msg = f"Host {resolved_target} is UP. Discovered {len(ports)} open port(s) with {risky_count} flagged as risky."
    else:
        diag_msg = f"Host {resolved_target} appears to be {host_status}."

    if line_callback:
        line_callback(f"[+] {diag_msg}")

    if conn is not None:
        log_event(
            conn,
            lock,
            module="scan",
            event_type="host_scan_completed",
            severity="info" if host_status == "up" else "warning",
            details={
                "target": target,
                "resolved_target": resolved_target,
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
                    "resolved_target": resolved_target,
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
        "resolved_target": resolved_target,
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
