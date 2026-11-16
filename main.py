#!/usr/bin/env python3
"""
main.py - Entry Point for Project ARGUS
Cyber Threat & Forensic Analysis Suite
Author: Muhammad Inshal
Platform: Kali Linux (exclusive)
"""

import argparse
import os
import sys

# Ensure local modules are found
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from core.controller import ThreatForensicSuite


def run_headless_demo(suite: ThreatForensicSuite):
    """
    Runs a non-interactive end-to-end forensic demonstration across all three modules.
    Useful for verification, headless environments, and test pipelines.
    """
    print("=" * 70)
    print("PROJECT ARGUS — CYBER THREAT & FORENSIC ANALYSIS SUITE")
    print("Automated Verification & Demonstration Pipeline")
    print("=" * 70)

    # 1. Packet Analyzer
    print("\n[*] Module A: Packet Analyzer (tshark)")
    sample_pcap = os.path.abspath("test_data/sample_traffic.pcap")
    if os.path.exists(sample_pcap):
        pcap_res = suite.analyze_capture(sample_pcap)
        print(f"  [+] Analyzed PCAP: {pcap_res.get('total_packets')} packets, {pcap_res.get('total_bytes')} bytes")
        print(f"  [+] Top talkers: {[t['ip'] for t in pcap_res.get('top_talkers', [])]}")
        print(f"  [+] Anomalies detected: {len(pcap_res.get('anomalies', []))}")
    else:
        print("  [!] Sample pcap not found at", sample_pcap)

    # 2. Vulnerability Scanner
    print("\n[*] Module B: Vulnerability Scanner (nmap)")
    target = "127.0.0.1"
    allowed, msg = suite.validate_target(target)
    print(f"  [+] Guardrail Check for {target}: {'ALLOWED' if allowed else 'BLOCKED'}")
    if allowed:
        scan_res = suite.scan_target(target, scan_type="-sT -F")
        print(f"  [+] Scan status: {scan_res.get('host_status')}, Open ports: {scan_res.get('open_ports_count')}")

    # 3. Memory Forensics
    print("\n[*] Module C: Memory Forensics (volatility3)")
    sample_dump = os.path.abspath("test_data/sample_memory.forensic")
    if os.path.exists(sample_dump):
        mem_res = suite.analyze_memory_dump(sample_dump, os_type="windows")
        print(f"  [+] Processes found: {mem_res.get('process_count')}")
        print(f"  [+] Sockets found: {mem_res.get('connection_count')}")
        print(f"  [+] Malfind injections: {mem_res.get('malfind_count')}")
        print(f"  [+] Critical alerts: {len([f for f in mem_res.get('suspicious_findings', []) if f['severity'] == 'critical'])}")

    # 4. Phase 6: Unified Timeline & Correlation
    print("\n[*] Phase 6: Unified Chronological Timeline & Correlation")
    timeline = suite.get_timeline()
    print(f"  [+] Total correlated timeline events: {len(timeline)}")
    for ev in timeline[:5]:
        print(f"      - [{ev['timestamp']}] [{ev['module'].upper()}] [{str(ev['severity']).upper()}] {ev['event_type']}")

    export_path = os.path.abspath("workspace/argus_demonstration_report.json")
    suite.export_report(export_path, format_type="json")
    print(f"  [+] Exported forensic investigation report to: {export_path}")

    stats = suite.get_statistics()
    print("\n[*] Unified Statistics:")
    print(f"  Total Events: {stats.get('total_events')}")
    print(f"  By Module:    {stats.get('by_module')}")
    print(f"  By Severity:  {stats.get('by_severity')}")
    print("=" * 70)
    print("[SUCCESS] ARGUS headless demonstration pipeline complete.\n")


def run_gui(suite: ThreatForensicSuite):
    """
    Launches the PyQt6 Dark SOC Dashboard.
    """
    from PyQt6.QtWidgets import QApplication
    from gui.main_window import MainWindow

    # Handle display environment fallback if headless
    if not os.environ.get("DISPLAY") and not os.environ.get("WAYLAND_DISPLAY"):
        os.environ["QT_QPA_PLATFORM"] = "offscreen"
        os.environ["QT_QPA_PLATFORMTHEME"] = ""

    app = QApplication(sys.argv)
    app.setApplicationName("Project ARGUS")

    window = MainWindow(suite)
    window.show()

    # If offscreen, don't block indefinitely
    if os.environ.get("QT_QPA_PLATFORM") == "offscreen":
        print("[*] Running in offscreen display mode.")
        return 0

    return app.exec()


def main():
    parser = argparse.ArgumentParser(
        description="Project ARGUS — Cyber Threat & Forensic Analysis Suite"
    )
    parser.add_argument(
        "--demo", action="store_true",
        help="Run headless end-to-end verification and export sample forensic report."
    )
    parser.add_argument(
        "--db", default="workspace/argus.db",
        help="Path to SQLite events database (default: workspace/argus.db)"
    )
    args = parser.parse_args()

    os.makedirs("workspace", exist_ok=True)
    suite = ThreatForensicSuite(db_path=args.db)

    try:
        if args.demo:
            run_headless_demo(suite)
            return 0
        else:
            return run_gui(suite)
    finally:
        suite.shutdown()


if __name__ == "__main__":
    sys.exit(main())
