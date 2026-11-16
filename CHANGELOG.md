# Changelog

All notable changes to **Project ARGUS** (Cyber Threat & Forensic Analysis Suite) are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] - 2026-11-16

### Added
- **Unified Chronological Timeline (Phase 6):** Cross-module event correlation table syncing Packet Analyzer, Nmap Scanner, and Memory Forensics events in UTC ISO-8601 order.
- **Unified Forensic Report Export:** Structured export to JSON and CSV formats with spreadsheet formula injection protection.
- **Module A: Packet Analyzer:**
  - Live promiscuous and filtered traffic capture via asynchronous TShark wrapper.
  - Offline `.pcap` / `.pcapng` deep packet inspection and protocol breakdown.
  - Top talkers volume calculation (frame count, byte totals, bandwidth percentage).
  - Cleartext HTTP credential / path discovery and TCP SYN scan heuristics.
- **Module B: Vulnerability Scanner:**
  - Fast, responsive Nmap orchestration (`-sV -T4 -Pn`) with XML streaming parser.
  - Strict input validation and target guardrails against private network ranges (`127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).
  - DNS resolution validation and CLI option injection prevention via `--` delimiter.
  - Informative diagnostic reporting for live hosts with closed/filtered ports.
- **Module C: Memory Forensics:**
  - Volatility 3 orchestration for Windows and Linux memory dump analysis (`.raw`, `.vmem`, `.dmp`, `.mem`).
  - Automated OS detection and architecture-specific plugin dispatch (`windows.*` vs `linux.*`).
  - Process pool scanning (`psscan`) correlated against active doubly-linked lists (`pslist`) to detect hidden or unlinked processes.
  - Unbacked executable memory region identification (`malfind`) with live disassembly and hex inspection.
  - Non-destructive image ingestion and SHA-256 integrity verification.
- **PyQt6 SOC Dashboard:**
  - Dark-themed cybersecurity operations dashboard with custom QSS stylesheet.
  - Signal-slot thread safety (`CaptureSignalBridge`) eliminating background UI segfaults.
  - Responsive metric cards, granular severity filtering, search indexing, and pagination.
  - Root execution detection and security status indicator.
- **Automated Verification Suite:**
  - End-to-end integration test (`tests/test_e2e_integration.py`).
  - Dedicated security hardening tests (`tests/test_phase7b_security.py`).
  - Dedicated correctness tests (`tests/test_phase7c_correctness.py`).
  - Standalone offline parser and concurrency tests (`tests/test_offline_parsers.py`).
  - GitHub Actions Continuous Integration workflow (`.github/workflows/ci.yml`).

### Security & Hardening
- Replaced all raw shell invocations (`shell=True`, `os.system`) with parameterized argument arrays.
- Enforced strict POSIX filesystem permissions (`0o700` directories, `0o600` capture files).
- Sanitized CSV exports against CSV / Formula Injection attacks (`=`, `+`, `-`, `@`, `\t`).
- Normalized IP inputs across decimal, octal, hex, and integer representations (`socket.inet_aton`).

### Licensing & Repo Hygiene
- Relicensed whole codebase under the permissive MIT License.
- Established Acceptable Use Guidelines under PECA 2016 for authorized laboratory testing.

