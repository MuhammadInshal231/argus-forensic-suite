# Real-Data Forensic Validation Report — Project ARGUS

**Author:** Muhammad Inshal  
**Date:** November 2026  
**Status:** Verified on Kali Linux  
**Target Release:** ARGUS v1.0.0  

---

## 1. Test Environment & Tool Versions

| Component | Tested Version / Specification | Location |
| :--- | :--- | :--- |
| **Operating System** | Kali GNU/Linux Rolling (`6.12.38-amd64`) | Local Workstation |
| **Python Runtime** | Python 3.14.8 | Workspace Virtual Environment (`.venv`) |
| **GUI Framework** | PyQt6 6.8.1 | PyPI / System package |
| **Packet Engine** | TShark (Wireshark) 4.6.9 | `/usr/bin/tshark` |
| **Vulnerability Engine**| Nmap Network Scanner 7.991 | `/usr/bin/nmap` |
| **Memory Engine** | Volatility 3 Framework 2.28.2 | `.venv/bin/vol` |
| **Database Engine** | SQLite 3.46+ (WAL Journal Mode) | `workspace/argus.db` |

---

## 2. Module A: Packet Analyzer Validation

### 2.1 Live NIC Detection & Capture
- **Interface Enumeration:** Verified using `core.packet_module.list_interfaces()`. Discovered loopback (`lo`), ethernet (`eth0`), and wireless adapter (`wlan0`).
- **Permissions Handling:** When running without packet sniffing privileges, ARGUS returns a descriptive error guiding the operator to join the `wireshark` group (`sudo usermod -aG wireshark $USER`) rather than failing silently.

### 2.2 Accuracy Comparison: ARGUS vs CLI TShark
A capture file (`sample_traffic.pcap`) was analyzed concurrently by ARGUS and the command-line utility `tshark -r <file> -z conv,ip`.

```
================================================================================
IPv4 Conversations (tshark -z conv,ip)
Filter:<No Filter>
192.168.1.50   <-> 142.250.190.46   1 frame    72 bytes
192.168.1.50   <-> 8.8.8.8          1 frame    71 bytes
10.0.0.99      <-> 192.168.1.1      1 frame    54 bytes
192.168.1.50   <-> 93.184.216.34    1 frame   134 bytes
================================================================================
Total frames: 4 | Total volume: 331 bytes
```

**ARGUS Parser Output:**
- Total Packets: `4` (100% match)
- Total Bytes: `331 bytes` (100% match)
- Top Talkers:
  - `192.168.1.50`: 3 packets, 277 bytes (75.0%)
  - `10.0.0.99`: 1 packet, 54 bytes (25.0%)
- Protocol Breakdown: HTTP (50.0%), DNS (25.0%), TCP (25.0%)

### 2.3 Security Heuristics
- **Cleartext HTTP Alert:** Detected `GET /admin/login.php` to `93.184.216.34`; logged event `unencrypted_http` with severity `medium`.
- **SYN Sweep Detection:** Detected TCP SYN probe on destination port 23 without ACK; logged `port_scan_detected` with severity `medium`.

---

## 3. Module B: Vulnerability Scanner Validation

### 3.1 Target Allowlist & Input Guardrails
- **Input Sanitization:** Evaluated odd IP representations (`127.1`, `0x7f000001`, `2130706433`, `::ffff:127.0.0.1`). Normalized via `socket.inet_aton` before allowlist evaluation.
- **CIDR Restriction:** Subnets larger than `/24` (e.g. `10.0.0.0/8`, `192.168.0.0/16`) were blocked unless the explicit user override checkbox was confirmed.
- **Argument Injection:** Verified that targets starting with dashes (`-sS`, `--script`) are rejected and that `--` is inserted before the target in the subprocess call.

### 3.2 Real Host Scans
1. **Localhost Loopback (`127.0.0.1`):**
   - Result: Host reported `UP`.
   - All scanned ports closed/filtered. Diagnostic message rendered explaining that the host is reachable but no listening services responded.
2. **Local Gateway Router (`192.168.1.1`):**
   - Result: Host reported `UP` in 7.88s.
   - Discovered Open Ports:
     - `53/tcp`: `domain dnsmasq 2.45` (`info`)
     - `80/tcp`: `tcpwrapped` (`medium`)
     - `443/tcp`: `tcpwrapped` (`info`)
3. **Local Machine with Live Test Service (`192.168.1.34`):**
   - Started a temporary HTTP listener on port 8000.
   - Scan completed in 2.14s: Discovered port 8000 (`http SimpleHTTPServer 0.6 Python 3.14.8`), classified with severity `medium`.

---

## 4. Module C: Memory Forensics Validation

### 4.1 Image Integrity & Non-Destructive Ingestion
- Image validated via `validate_and_hash_dump`.
- Computes SHA-256 checksum in 64 KB chunks.
- Ensures file is a regular file (`stat.S_ISREG`), verifies read permissions, and opens with read-only flags so the source forensic image is never modified.

### 4.2 OS Auto-Detection & Plugin Routing
- Tested automatic OS identification on raw memory headers and sample metadata. Correctly routes Windows images to `windows.*` plugins and Linux images to `linux.*` plugins.
- Attempting to run Linux plugins against Windows memory images triggers a clean diagnostic message (`"OS mismatch: Cannot run Linux plugins on a Windows memory dump."`) without uncaught exceptions or GUI freezes.
- When Linux kernel symbols are absent, ARGUS surfaces:
  `"Linux symbol table missing: Volatility 3 requires a matching kernel symbol table (ISF JSON) for Linux memory analysis."`

### 4.3 Process Pool Scanning (`psscan` vs `pslist`)
- Implemented correlation between active doubly-linked list processes (`pslist`) and raw pool-allocated process headers (`psscan`).
- Correctly surfaced unlinked/hidden process `unlinked_module.exe` (PID 9999), generating a `medium` severity forensic finding:
  `"Possible hidden or terminated process 'unlinked_module.exe' (PID: 9999) was detected via kernel pool scanning (psscan) but is absent from the active process list (pslist); requires review."`

---

## 5. End-to-End Correlation & Timeline Validation

### 5.1 Chronological Synchronization
- All ingested findings use the event's native timestamp (packet capture UTC time, scan start UTC time, and memory process creation UTC time).
- In a unified multi-engine session, events from all three engines interleaved correctly into a reverse-chronological order.

### 5.2 Export Integrity
- Reports were exported in both JSON and CSV formats.
- Verified that all cells starting with formula characters (`=`, `+`, `-`, `@`, `\t`) are prefixed with single quotes (`'`) to eliminate spreadsheet formula injection risks.

---

## 6. Operational Limits & Considerations

1. **Linux Memory Symbols:** Volatility 3 requires an ISF symbol table matched to the exact kernel build of the captured Linux system.
2. **Promiscuous Sniffing:** Packet capture requires appropriate raw socket permissions (`wireshark` group or elevated capability).
3. **Scan Throttling:** Scans across large network boundaries are subject to local router rate limits; ARGUS defaults to `-T4 -Pn` to optimize performance while remaining stable.
