"""
gui/scan_tab.py - Vulnerability Scanner GUI Tab (nmap orchestrator)
Features dynamic host IP detection, target authorization guardrails, real-time live streaming,
and optimized high-performance Nmap scan profiles.
"""

from typing import Any, Dict, Optional

from PyQt6.QtCore import QThread, pyqtSignal, Qt
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QProgressBar,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from core.controller import ThreatForensicSuite
from core.scan_module import get_local_host_ips


class ScanWorker(QThread):
    """Asynchronous background worker for executing Nmap scans with live line streaming."""
    scan_completed = pyqtSignal(dict)
    scan_failed = pyqtSignal(str)
    line_streamed = pyqtSignal(str)

    def __init__(self, suite: ThreatForensicSuite, target: str, scan_type: str, allow_custom: bool):
        super().__init__()
        self.suite = suite
        self.target = target
        self.scan_type = scan_type
        self.allow_custom = allow_custom

    def run(self):
        try:
            result = self.suite.scan_target(
                target=self.target,
                scan_type=self.scan_type,
                allow_custom=self.allow_custom,
                line_callback=lambda line: self.line_streamed.emit(line)
            )
            if result.get("success"):
                self.scan_completed.emit(result)
            else:
                self.scan_failed.emit(result.get("error", "Scan failed without error output."))
        except Exception as exc:
            self.scan_failed.emit(str(exc))


class ScanTab(QWidget):
    """PyQt6 tab for network and port vulnerability scanning."""

    def __init__(self, suite: ThreatForensicSuite, parent=None):
        super().__init__(parent)
        self.suite = suite
        self.worker: Optional[ScanWorker] = None
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(16, 16, 16, 16)

        # 1. Target Controls Card
        control_card = QFrame()
        control_card.setProperty("class", "CardFrame")
        ctrl_layout = QVBoxLayout(control_card)

        title = QLabel("Target Specification & Safety Guardrails")
        title.setProperty("class", "SectionTitle")
        ctrl_layout.addWidget(title)

        # Quick Target Selector Buttons
        quick_row = QHBoxLayout()
        quick_row.addWidget(QLabel("Quick Target Selection:"))

        btn_lo = QPushButton("127.0.0.1 (Loopback)")
        btn_lo.setStyleSheet("padding: 3px 8px; font-size: 11px;")
        btn_lo.clicked.connect(lambda: self.target_input.setText("127.0.0.1"))
        quick_row.addWidget(btn_lo)

        # Discover dynamic host IPs
        host_ips = [ip for ip in get_local_host_ips() if ip not in ("127.0.0.1", "::1")]
        for h_ip in host_ips[:2]:
            btn_host = QPushButton(f"{h_ip} (Host NIC)")
            btn_host.setStyleSheet("padding: 3px 8px; font-size: 11px;")
            btn_host.clicked.connect(lambda checked, ip=h_ip: self.target_input.setText(ip))
            quick_row.addWidget(btn_host)

        btn_gw = QPushButton("192.168.1.1 (Gateway Router)")
        btn_gw.setStyleSheet("padding: 3px 8px; font-size: 11px;")
        btn_gw.clicked.connect(lambda: self.target_input.setText("192.168.1.1"))
        quick_row.addWidget(btn_gw)

        quick_row.addStretch()
        ctrl_layout.addLayout(quick_row)

        inputs_layout = QHBoxLayout()

        # Target Input
        target_vbox = QVBoxLayout()
        target_vbox.addWidget(QLabel("Target IP / Subnet:"))
        self.target_input = QLineEdit("127.0.0.1")
        self.target_input.setPlaceholderText("e.g. 127.0.0.1, 192.168.1.100, 192.168.1.1")
        self.target_input.textChanged.connect(self._validate_target_ui)
        target_vbox.addWidget(self.target_input)
        inputs_layout.addLayout(target_vbox, stretch=3)

        # Scan Profile Dropdown
        profile_vbox = QVBoxLayout()
        profile_vbox.addWidget(QLabel("Optimized Scan Profile:"))
        self.profile_combo = QComboBox()
        self.profile_combo.addItem("⚡ Fast Port Scan (-F -T4 -Pn) [~2 sec]", "-F -T4 -Pn")
        self.profile_combo.addItem("🔍 Service & Version Detection (-sV -T4 --open -Pn) [~5-10 sec]", "-sV -T4 --open -Pn")
        self.profile_combo.addItem("🚀 Quick TCP Connect (-sT -F -T4 -Pn) [Non-root]", "-sT -F -T4 -Pn")
        self.profile_combo.addItem("🛡️ Vulnerability & Script Audit (-sV -sC -T4 --open -Pn)", "-sV -sC -T4 --open -Pn")
        self.profile_combo.addItem("🎯 Common Web/Admin Ports (21-445, 3389, 8080)", "-p 21,22,23,25,53,80,110,135,139,143,443,445,1433,3306,3389,5900,8080 -sV -T4 --open -Pn")
        profile_vbox.addWidget(self.profile_combo)
        inputs_layout.addLayout(profile_vbox, stretch=4)

        # Scan Button
        btn_vbox = QVBoxLayout()
        btn_vbox.addWidget(QLabel("Action:"))
        self.scan_btn = QPushButton("▶ Launch Nmap Scan")
        self.scan_btn.setProperty("class", "PrimaryBtn")
        self.scan_btn.clicked.connect(self._start_scan)
        btn_vbox.addWidget(self.scan_btn)
        inputs_layout.addLayout(btn_vbox, stretch=2)

        ctrl_layout.addLayout(inputs_layout)

        # Authorization Override Checkbox & Guardrail Badge
        status_row = QHBoxLayout()
        self.custom_auth_checkbox = QCheckBox("Authorize Custom / External Target (I certify ownership/authorization under PECA 2016)")
        self.custom_auth_checkbox.setStyleSheet("font-size: 11px; color: #8b949e;")
        self.custom_auth_checkbox.toggled.connect(lambda: self._validate_target_ui(self.target_input.text()))
        status_row.addWidget(self.custom_auth_checkbox)

        self.guardrail_badge = QLabel()
        self.guardrail_badge.setStyleSheet("font-size: 11px; font-weight: bold;")
        status_row.addWidget(self.guardrail_badge, alignment=Qt.AlignmentFlag.AlignRight)
        ctrl_layout.addLayout(status_row)

        self._validate_target_ui(self.target_input.text())

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0)
        self.progress_bar.setVisible(False)
        ctrl_layout.addWidget(self.progress_bar)

        layout.addWidget(control_card)

        # 2. Metric Summary Cards
        metric_layout = QHBoxLayout()
        self.card_host = self._create_metric_card("TARGET HOST", "127.0.0.1", "#58a6ff")
        self.card_status = self._create_metric_card("HOST STATUS", "IDLE", "#8b949e")
        self.card_ports = self._create_metric_card("OPEN PORTS", "0", "#3fb950")
        self.card_risky = self._create_metric_card("RISKY SERVICES", "0", "#d29922")

        metric_layout.addWidget(self.card_host)
        metric_layout.addWidget(self.card_status)
        metric_layout.addWidget(self.card_ports)
        metric_layout.addWidget(self.card_risky)
        layout.addLayout(metric_layout)

        # 3. Main Splitter: Results Table (Top) & Live Diagnostic Log (Bottom)
        splitter = QSplitter(Qt.Orientation.Vertical)

        # Results Table Card
        table_card = QFrame()
        table_card.setProperty("class", "CardFrame")
        table_layout = QVBoxLayout(table_card)
        table_layout.addWidget(QLabel("Discovered Ports, Services & Vulnerability Exposure"))

        self.results_table = QTableWidget(0, 7)
        self.results_table.setHorizontalHeaderLabels([
            "Port", "Proto", "State", "Service", "Version", "Risk Level", "Forensic Risk Assessment"
        ])
        header = self.results_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)
        self.results_table.verticalHeader().setVisible(False)
        table_layout.addWidget(self.results_table)

        splitter.addWidget(table_card)

        # Live Diagnostic Log Drawer
        raw_card = QFrame()
        raw_card.setProperty("class", "CardFrame")
        raw_layout = QVBoxLayout(raw_card)
        raw_layout.addWidget(QLabel("Live Diagnostic Feed & Real-time Progress"))

        self.raw_output_view = QTextEdit()
        self.raw_output_view.setReadOnly(True)
        self.raw_output_view.setPlaceholderText("Real-time scan telemetry, live progress, and XML feed appear here...")
        raw_layout.addWidget(self.raw_output_view)

        splitter.addWidget(raw_card)
        splitter.setSizes([320, 150])

        layout.addWidget(splitter, stretch=1)

    def _create_metric_card(self, title: str, initial_val: str, color_hex: str) -> QFrame:
        card = QFrame()
        card.setProperty("class", "MetricCard")
        vbox = QVBoxLayout(card)
        vbox.setContentsMargins(8, 8, 8, 8)
        lbl_title = QLabel(title)
        lbl_title.setProperty("class", "MetricLabel")
        lbl_val = QLabel(initial_val)
        lbl_val.setProperty("class", "MetricValue")
        lbl_val.setStyleSheet(f"color: {color_hex};")
        card._lbl_val = lbl_val
        vbox.addWidget(lbl_title)
        vbox.addWidget(lbl_val)
        return card

    def _validate_target_ui(self, target: str):
        allow_custom = self.custom_auth_checkbox.isChecked()
        allowed, msg = self.suite.validate_target(target, allow_custom=allow_custom)
        if allowed:
            self.guardrail_badge.setText(f"✓ AUTHORIZED TARGET")
            self.guardrail_badge.setStyleSheet("color: #3fb950; font-weight: bold; font-size: 11px;")
            self.scan_btn.setEnabled(True)
        else:
            self.guardrail_badge.setText(f"✕ GUARDRAIL BLOCKED")
            self.guardrail_badge.setStyleSheet("color: #f85149; font-weight: bold; font-size: 11px;")
            self.scan_btn.setEnabled(False)

    def _start_scan(self):
        target = self.target_input.text().strip()
        scan_type = self.profile_combo.currentData()
        allow_custom = self.custom_auth_checkbox.isChecked()

        allowed, msg = self.suite.validate_target(target, allow_custom=allow_custom)
        if not allowed:
            self.raw_output_view.setText(f"[SECURITY BLOCKED] {msg}")
            return

        self.scan_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.card_host._lbl_val.setText(target)
        self.card_status._lbl_val.setText("SCANNING...")
        self.card_status._lbl_val.setStyleSheet("color: #58a6ff;")
        self.raw_output_view.clear()
        self.raw_output_view.append(f"[*] Starting high-performance Nmap scan ({scan_type}) against target {target}...")

        self.worker = ScanWorker(self.suite, target, scan_type, allow_custom=allow_custom)
        self.worker.line_streamed.connect(self._on_live_stream_line)
        self.worker.scan_completed.connect(self._on_scan_completed)
        self.worker.scan_failed.connect(self._on_scan_failed)
        self.worker.start()

    def _on_live_stream_line(self, line: str):
        self.raw_output_view.append(line)

    def _on_scan_completed(self, result: Dict[str, Any]):
        self.scan_btn.setEnabled(True)
        self.progress_bar.setVisible(False)

        host_status = result.get("host_status", "unknown").upper()
        ports = result.get("ports", [])
        risky_count = result.get("risky_services_count", 0)

        # Update Metrics
        self.card_status._lbl_val.setText(host_status)
        self.card_status._lbl_val.setStyleSheet("color: #3fb950;" if host_status == "UP" else "color: #d29922;")
        self.card_ports._lbl_val.setText(str(len(ports)))
        self.card_risky._lbl_val.setText(str(risky_count))
        self.card_risky._lbl_val.setStyleSheet("color: #f85149;" if risky_count > 0 else "color: #3fb950;")

        # Populate Results Table
        self.results_table.setRowCount(0)
        for row_idx, p in enumerate(ports):
            self.results_table.insertRow(row_idx)

            self.results_table.setItem(row_idx, 0, QTableWidgetItem(str(p["port"])))
            self.results_table.setItem(row_idx, 1, QTableWidgetItem(p["protocol"].upper()))
            self.results_table.setItem(row_idx, 2, QTableWidgetItem(p["state"]))
            self.results_table.setItem(row_idx, 3, QTableWidgetItem(p["service"]))
            self.results_table.setItem(row_idx, 4, QTableWidgetItem(p["version"]))

            sev = p.get("severity", "info").upper()
            sev_item = QTableWidgetItem(sev)
            if sev == "CRITICAL":
                sev_item.setForeground(Qt.GlobalColor.red)
            elif sev == "WARNING":
                sev_item.setForeground(Qt.GlobalColor.yellow)
            else:
                sev_item.setForeground(Qt.GlobalColor.cyan)
            self.results_table.setItem(row_idx, 5, sev_item)

            self.results_table.setItem(row_idx, 6, QTableWidgetItem(p.get("risk_description", "")))

        # Diagnostic summary
        diag = result.get("diagnostic_message", "")
        self.raw_output_view.append(f"\n[+] Scan finished in {result.get('elapsed_seconds')}s.\n[+] {diag}")

    def _on_scan_failed(self, error_msg: str):
        self.scan_btn.setEnabled(True)
        self.progress_bar.setVisible(False)
        self.card_status._lbl_val.setText("FAILED")
        self.card_status._lbl_val.setStyleSheet("color: #f85149;")
        self.raw_output_view.append(f"\n[ERROR] Scan execution failed:\n{error_msg}")
