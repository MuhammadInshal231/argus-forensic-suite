"""
core/packet_module.py - Packet Capture and Traffic Analysis Module (tshark wrapper)
Performs non-root live captures and extracts security-relevant traffic summaries.
"""

import collections
import json
import os
import re
import socket
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

from core.db import log_event
from core.process_runner import StreamingProcess, run_command


COMMON_SAFE_PORTS = {
    22: "SSH",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    123: "NTP",
    443: "HTTPS",
    8080: "HTTP-ALT",
    8443: "HTTPS-ALT",
}


def list_interfaces() -> List[Dict[str, str]]:
    """
    Discovers available network capture interfaces via tshark -D with /sys/class/net fallback.
    Returns list of dicts: [{'index': '1', 'name': 'lo', 'description': 'Loopback'}]
    """
    interfaces: List[Dict[str, str]] = []

    # 1. Try tshark -D
    stdout, stderr, rc = run_command(["tshark", "-D"])
    if rc == 0 and stdout:
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            # Pattern: "1. eth0 (Ethernet)" or "4. lo (Loopback)"
            m = re.match(r"^(\d+)\.\s+([^\s\(]+)(?:\s+\((.*)\))?", line)
            if m:
                idx, name, desc = m.groups()
                interfaces.append({
                    "index": idx,
                    "name": name,
                    "description": desc or name
                })
        if interfaces:
            return interfaces

    # 2. Fallback to /sys/class/net
    sys_net = "/sys/class/net"
    if os.path.exists(sys_net):
        try:
            for idx, iface in enumerate(os.listdir(sys_net), start=1):
                interfaces.append({
                    "index": str(idx),
                    "name": iface,
                    "description": "Loopback" if iface == "lo" else f"Network interface {iface}"
                })
        except Exception:
            pass

    if not interfaces:
        interfaces.append({"index": "1", "name": "lo", "description": "Loopback"})
        interfaces.append({"index": "2", "name": "any", "description": "Pseudo-device all interfaces"})

    return interfaces


def start_capture(
    interface: str = "lo",
    duration: Optional[int] = None,
    bpf_filter: Optional[str] = None,
    output_pcap: Optional[str] = None,
    line_callback: Optional[Callable[[str], None]] = None,
    finished_callback: Optional[Callable[[int], None]] = None
) -> Tuple[str, StreamingProcess]:
    """
    Launches a live packet capture using tshark in a non-blocking StreamingProcess.
    
    :param interface: Interface name (e.g. 'lo', 'eth0', 'any')
    :param duration: Maximum capture time in seconds
    :param bpf_filter: Optional BPF filter expression (e.g. 'tcp port 80')
    :param output_pcap: Target .pcap path (defaults to workspace/capture_<timestamp>.pcap)
    :param line_callback: Callback for streaming stdout/stderr lines
    :param finished_callback: Callback invoked when capture process exits
    :return: (output_pcap_path, StreamingProcess_instance)
    """
    if not output_pcap:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        os.makedirs("workspace", exist_ok=True)
        output_pcap = os.path.abspath(f"workspace/capture_{timestamp}.pcap")
    else:
        output_pcap = os.path.abspath(output_pcap)
        os.makedirs(os.path.dirname(output_pcap), exist_ok=True)

    cmd = ["tshark", "-i", interface, "-w", output_pcap]

    if duration and duration > 0:
        cmd.extend(["-a", f"duration:{int(duration)}"])

    if bpf_filter and bpf_filter.strip():
        cmd.extend(["-f", bpf_filter.strip()])

    sp = StreamingProcess()
    sp.start(cmd, line_callback=line_callback, finished_callback=finished_callback)
    return output_pcap, sp


def stop_capture(process: StreamingProcess, timeout: float = 3.0) -> int:
    """
    Terminates the active capture process group gracefully.
    """
    if process and process.is_running:
        return process.stop(timeout=timeout)
    return 0


def analyze_pcap(
    pcap_path: str,
    conn=None,
    lock=None,
    display_filter: Optional[str] = None
) -> Dict[str, Any]:
    """
    Analyzes a .pcap file using tshark JSON output and computes:
    - Packet volume & total bytes
    - Top 10 talkers (source IPs)
    - Protocol breakdown
    - Unusual ports & potential anomalies (SYN scans, cleartext traffic)
    Logs findings to unified SQLite events table.
    """
    if not os.path.exists(pcap_path) or os.path.getsize(pcap_path) == 0:
        return {
            "success": False,
            "error": f"Pcap file not found or empty: {pcap_path}",
            "total_packets": 0,
            "total_bytes": 0,
            "top_talkers": [],
            "protocols": {},
            "unusual_ports": [],
            "anomalies": []
        }

    cmd = ["tshark", "-r", pcap_path, "-T", "json"]
    if display_filter and display_filter.strip():
        cmd.extend(["-Y", display_filter.strip()])

    stdout, stderr, rc = run_command(cmd, timeout=120)

    if rc != 0 and not stdout:
        return {
            "success": False,
            "error": f"tshark analysis failed: {stderr}",
            "total_packets": 0,
            "total_bytes": 0,
            "top_talkers": [],
            "protocols": {},
            "unusual_ports": [],
            "anomalies": []
        }

    try:
        packets = json.loads(stdout)
    except json.JSONDecodeError as exc:
        return {
            "success": False,
            "error": f"Failed to parse tshark JSON output: {exc}",
            "total_packets": 0,
            "total_bytes": 0,
            "top_talkers": [],
            "protocols": {},
            "unusual_ports": [],
            "anomalies": []
        }

    total_packets = len(packets)
    total_bytes = 0
    src_ip_counter: collections.Counter = collections.Counter()
    src_ip_bytes: collections.Counter = collections.Counter()
    protocol_counter: collections.Counter = collections.Counter()
    dst_ports_counter: collections.Counter = collections.Counter()
    syn_scan_tracker: Dict[str, set] = collections.defaultdict(set)
    unusual_ports_found: Dict[int, Dict[str, Any]] = {}
    anomalies: List[Dict[str, Any]] = []

    for pkt in packets:
        source = pkt.get("_source", {})
        layers = source.get("layers", {})

        # Frame layer
        frame = layers.get("frame", {})
        pkt_len = int(frame.get("frame.len", 0))
        total_bytes += pkt_len
        protocols_str = frame.get("frame.protocols", "")

        # Protocol categorization
        proto_tag = "OTHER"
        if "http" in protocols_str or "tls" in protocols_str or "ssl" in protocols_str:
            proto_tag = "HTTPS/TLS" if ("tls" in protocols_str or "ssl" in protocols_str) else "HTTP"
        elif "dns" in protocols_str:
            proto_tag = "DNS"
        elif "tcp" in protocols_str:
            proto_tag = "TCP"
        elif "udp" in protocols_str:
            proto_tag = "UDP"
        elif "icmp" in protocols_str:
            proto_tag = "ICMP"
        elif "arp" in protocols_str:
            proto_tag = "ARP"

        protocol_counter[proto_tag] += 1

        # IP layer
        ip_layer = layers.get("ip", {})
        src_ip = ip_layer.get("ip.src")
        dst_ip = ip_layer.get("ip.dst")

        if src_ip:
            src_ip_counter[src_ip] += 1
            src_ip_bytes[src_ip] += pkt_len

        # TCP / UDP layer
        tcp_layer = layers.get("tcp", {})
        udp_layer = layers.get("udp", {})

        dst_port = None
        src_port = None

        if tcp_layer:
            dst_port_str = tcp_layer.get("tcp.dstport")
            src_port_str = tcp_layer.get("tcp.srcport")
            flags_str = tcp_layer.get("tcp.flags", "0")
            if dst_port_str and dst_port_str.isdigit():
                dst_port = int(dst_port_str)
            if src_port_str and src_port_str.isdigit():
                src_port = int(src_port_str)

            # Check SYN scan heuristic: SYN flag set (0x02) without ACK
            try:
                flags_val = int(flags_str, 16) if flags_str.startswith("0x") else int(flags_str)
                if (flags_val & 0x02) and not (flags_val & 0x10):
                    if src_ip and dst_port:
                        syn_scan_tracker[src_ip].add(dst_port)
            except Exception:
                pass

        elif udp_layer:
            dst_port_str = udp_layer.get("udp.dstport")
            src_port_str = udp_layer.get("udp.srcport")
            if dst_port_str and dst_port_str.isdigit():
                dst_port = int(dst_port_str)
            if src_port_str and src_port_str.isdigit():
                src_port = int(src_port_str)

        if dst_port:
            dst_ports_counter[dst_port] += 1
            if dst_port not in COMMON_SAFE_PORTS:
                if dst_port not in unusual_ports_found:
                    unusual_ports_found[dst_port] = {
                        "port": dst_port,
                        "packet_count": 0,
                        "proto": "TCP" if tcp_layer else "UDP",
                        "sample_dst_ip": dst_ip
                    }
                unusual_ports_found[dst_port]["packet_count"] += 1

        # Check for unencrypted HTTP traffic anomaly
        if "http" in layers:
            http_layer = layers["http"]
            uri = http_layer.get("http.request.uri")
            host = http_layer.get("http.host")
            if uri:
                anomalies.append({
                    "type": "unencrypted_http",
                    "severity": "warning",
                    "description": f"Cleartext HTTP request observed: {host or ''}{uri}",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip
                })

    # Detect Port Scan / SYN Flood Anomaly
    for scanner_ip, targeted_ports in syn_scan_tracker.items():
        if len(targeted_ports) >= 3:
            anomalies.append({
                "type": "port_scan_detected",
                "severity": "critical",
                "description": f"Potential port sweep from {scanner_ip}: targeted {len(targeted_ports)} unique ports",
                "src_ip": scanner_ip,
                "targeted_ports": sorted(list(targeted_ports))[:20]
            })

    # Compute Top 10 Talkers
    top_talkers = []
    for ip, count in src_ip_counter.most_common(10):
        b_vol = src_ip_bytes.get(ip, 0)
        pct = round((count / total_packets * 100), 2) if total_packets > 0 else 0
        top_talkers.append({
            "ip": ip,
            "packets": count,
            "bytes": b_vol,
            "percentage": pct
        })

    # Compute Protocol Percentages
    proto_breakdown = {}
    for proto, count in protocol_counter.items():
        pct = round((count / total_packets * 100), 2) if total_packets > 0 else 0
        proto_breakdown[proto] = {"count": count, "percentage": pct}

    unusual_ports_list = sorted(
        list(unusual_ports_found.values()),
        key=lambda x: x["packet_count"],
        reverse=True
    )[:15]

    # Log Events to Unified DB
    if conn is not None:
        # Summary event
        log_event(
            conn,
            lock,
            module="packet",
            event_type="pcap_analysis_completed",
            severity="info",
            details={
                "pcap_file": os.path.basename(pcap_path),
                "total_packets": total_packets,
                "total_bytes": total_bytes,
                "top_talker": top_talkers[0]["ip"] if top_talkers else "None",
                "anomalies_count": len(anomalies)
            }
        )

        # Log security anomalies
        for anom in anomalies:
            log_event(
                conn,
                lock,
                module="packet",
                event_type=anom["type"],
                severity=anom["severity"],
                details=anom
            )

        # Log significant unusual ports
        for up in unusual_ports_list:
            if up["packet_count"] >= 1:
                log_event(
                    conn,
                    lock,
                    module="packet",
                    event_type="unusual_port_traffic",
                    severity="warning" if up["port"] in (23, 21, 445, 3389) else "info",
                    details=up
                )

    return {
        "success": True,
        "pcap_file": pcap_path,
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "top_talkers": top_talkers,
        "protocols": proto_breakdown,
        "unusual_ports": unusual_ports_list,
        "anomalies": anomalies
    }
