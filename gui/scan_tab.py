"""
gui/scan_tab.py - Vulnerability Scanner GUI Tab (nmap orchestrator)
Features target allowlist badge, asynchronous scanning, and structured risk assessment.
"""

from typing import Any, Dict, Optional

from PyQt6.QtCore import QThread, pyqtSignal, Qt
from PyQt6.QtWidgets import (
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
    QComboBox,
)

from core.controller import ThreatForensicSuite


class ScanWorker(QThread):
    """Asynchronous background worker for executing Nmap scans."""
    scan_completed = pyqtSignal(dict)
    scan_failed = pyqtSignal(str)

    def __init__(self, suite: ThreatForensicSuite, target: str, scan_type: str):
        super().__init__()
        self.suite = suite
        self.target = target
        self.scan_type = scan_type

    def run(self):
        try:
            result = self.suite.scan_target(self.target, self.scan_type)
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

        inputs_layout = QHBoxLayout()

        # Target Input
        target_vbox = QVBoxLayout()
        target_vbox.addWidget(QLabel("Target IP / Subnet (RFC 1918 / Localhost only):"))
        self.target_input = QLineEdit("127.0.0.1")
        self.target_input.setPlaceholderText("e.g. 127.0.0.1, 192.168.1.100")
        self.target_input.textChanged.connect(self._validate_target_ui)
        target_vbox.addWidget(self.target_input)
        inputs_layout.addLayout(target_vbox, stretch=3)

        # Scan Profile Dropdown
        profile_vbox = QVBoxLayout()
        profile_vbox.addWidget(QLabel("Scan Profile:"))
        self.profile_combo = QComboBox()
        self.profile_combo.addItem("Service & Version Detection (-sV)", "-sV")
        self.profile_combo.addItem("Fast Version Scan (-F -sV)", "-F -sV")
        self.profile_combo.addItem("TCP Connect Full Scan (-sT -sV)", "-sT -sV")
        self.profile_combo.addItem("Comprehensive Lab Audit (-sT -sV -sC -Pn)", "-sT -sV -sC -Pn")
        profile_vbox.addWidget(self.profile_combo)
        inputs_layout.addLayout(profile_vbox, stretch=3)

        # Scan Button
        btn_vbox = QVBoxLayout()
        btn_vbox.addWidget(QLabel("Action:"))
        self.scan_btn = QPushButton("▶ Launch Nmap Scan")
        self.scan_btn.setProperty("class", "PrimaryBtn")
        self.scan_btn.clicked.connect(self._start_scan)
        btn_vbox.addWidget(self.scan_btn)
        inputs_layout.addLayout(btn_vbox, stretch=2)

        ctrl_layout.addLayout(inputs_layout)

        # Allowlist Security Badge
        self.guardrail_badge = QLabel()
        self.guardrail_badge.setStyleSheet("font-size: 11px; padding: 4px; font-weight: bold;")
        ctrl_layout.addWidget(self.guardrail_badge)
        self._validate_target_ui(self.target_input.text())

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0) # indeterminate
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

        # 3. Main Splitter: Results Table (Top) & Raw Output / Assessment (Bottom)
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

        # Raw Output Drawer
        raw_card = QFrame()
        raw_card.setProperty("class", "CardFrame")
        raw_layout = QVBoxLayout(raw_card)
        raw_layout.addWidget(QLabel("Raw Nmap XML / Diagnostic Feed"))

        self.raw_output_view = QTextEdit()
        self.raw_output_view.setReadOnly(True)
        self.raw_output_view.setPlaceholderText("Scan output and XML telemetry will be logged here...")
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
        card._lbl_val = lbl_val  # save reference
        vbox.addWidget(lbl_title)
        vbox.addWidget(lbl_val)
        return card

    def _validate_target_ui(self, target: str):
        allowed, msg = self.suite.validate_target(target)
        if allowed:
            self.guardrail_badge.setText(f"✓ AUTHORIZED TARGET: {msg}")
            self.guardrail_badge.setStyleSheet("color: #3fb950; font-weight: bold; font-size: 11px;")
            self.scan_btn.setEnabled(True)
        else:
            self.guardrail_badge.setText(f"✕ GUARDRAIL BLOCKED: {msg}")
            self.guardrail_badge.setStyleSheet("color: #f85149; font-weight: bold; font-size: 11px;")
            self.scan_btn.setEnabled(False)

    def _start_scan(self):
        target = self.target_input.text().strip()
        scan_type = self.profile_combo.currentData()

        allowed, msg = self.suite.validate_target(target)
        if not allowed:
            self.raw_output_view.setText(f"[SECURITY BLOCKED] {msg}")
            return

        self.scan_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.card_host._lbl_val.setText(target)
        self.card_status._lbl_val.setText("SCANNING...")
        self.card_status._lbl_val.setStyleSheet("color: #58a6ff;")
        self.raw_output_view.setText(f"[*] Executing Nmap scan ({scan_type}) against authorized target {target}...")

        self.worker = ScanWorker(self.suite, target, scan_type)
        self.worker.scan_completed.connect(self._on_scan_completed)
        self.worker.scan_failed.connect(self._on_scan_failed)
        self.worker.start()

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

            # Severity badge
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

        # Update Raw XML view
        raw_xml = result.get("raw_xml", "")
        self.raw_output_view.setText(f"[+] Scan finished in {result.get('elapsed_seconds')}s.\n\n{raw_xml}")

    def _on_scan_failed(self, error_msg: str):
        self.scan_btn.setEnabled(True)
        self.progress_bar.setVisible(False)
        self.card_status._lbl_val.setText("FAILED")
        self.card_status._lbl_val.setStyleSheet("color: #f85149;")
        self.raw_output_view.setText(f"[ERROR] Scan execution failed:\n{error_msg}")
