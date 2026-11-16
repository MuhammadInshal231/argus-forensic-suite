"""
gui/packet_tab.py - Packet Analyzer GUI Tab (tshark orchestrator)
Features non-root live capture, BPF filters, offline pcap analysis, and top-talker traffic metrics.
"""

import os
from typing import Any, Dict, Optional

from PyQt6.QtCore import QObject, QThread, QTimer, pyqtSignal, Qt
from PyQt6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QSplitter,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from core.controller import ThreatForensicSuite


class CaptureSignalBridge(QObject):
    """Thread-safe Qt signal bridge to transfer live streaming lines from background threads to GUI."""
    line_received = pyqtSignal(str)
    capture_finished = pyqtSignal(int)


class PcapAnalysisWorker(QThread):
    """Background worker for analyzing offline .pcap files via tshark."""
    analysis_completed = pyqtSignal(dict)
    analysis_failed = pyqtSignal(str)

    def __init__(self, suite: ThreatForensicSuite, pcap_path: str):
        super().__init__()
        self.suite = suite
        self.pcap_path = pcap_path

    def run(self):
        try:
            result = self.suite.analyze_capture(self.pcap_path)
            if result.get("success"):
                self.analysis_completed.emit(result)
            else:
                self.analysis_failed.emit(result.get("error", "PCAP analysis failed."))
        except Exception as exc:
            self.analysis_failed.emit(str(exc))


class PacketTab(QWidget):
    """PyQt6 tab for live network packet capture and forensic traffic analysis."""

    def __init__(self, suite: ThreatForensicSuite, parent=None):
        super().__init__(parent)
        self.suite = suite
        self.analysis_worker: Optional[PcapAnalysisWorker] = None
        self._capture_seconds = 0
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._update_timer)
        
        # Thread-safe Qt signal bridge for live stream lines
        self.signal_bridge = CaptureSignalBridge()
        self.signal_bridge.line_received.connect(self._on_capture_line, Qt.ConnectionType.QueuedConnection)
        self.signal_bridge.capture_finished.connect(self._on_capture_finished, Qt.ConnectionType.QueuedConnection)
        
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(16, 16, 16, 16)

        # 1. Dual Control Panels (Live Capture & Offline PCAP)
        top_panels = QHBoxLayout()

        # Left Panel: Live Capture Controls
        live_card = QFrame()
        live_card.setProperty("class", "CardFrame")
        live_layout = QVBoxLayout(live_card)
        live_title = QLabel("Live Packet Capture (tshark CLI)")
        live_title.setProperty("class", "SectionTitle")
        live_layout.addWidget(live_title)

        live_row1 = QHBoxLayout()
        # Interface dropdown
        iface_vbox = QVBoxLayout()
        iface_vbox.addWidget(QLabel("Interface:"))
        self.iface_combo = QComboBox()
        self._populate_interfaces()
        iface_vbox.addWidget(self.iface_combo)
        live_row1.addLayout(iface_vbox, stretch=3)

        # Duration
        dur_vbox = QVBoxLayout()
        dur_vbox.addWidget(QLabel("Duration (s, 0=manual):"))
        self.duration_spin = QSpinBox()
        self.duration_spin.setRange(0, 3600)
        self.duration_spin.setValue(10)
        dur_vbox.addWidget(self.duration_spin)
        live_row1.addLayout(dur_vbox, stretch=2)
        live_layout.addLayout(live_row1)

        # BPF Filter
        live_layout.addWidget(QLabel("BPF Capture Filter (optional, e.g. 'tcp port 80'):"))
        self.bpf_input = QLineEdit()
        self.bpf_input.setPlaceholderText("e.g. tcp port 80 or udp port 53")
        live_layout.addWidget(self.bpf_input)

        # Capture Buttons
        btn_layout = QHBoxLayout()
        self.start_btn = QPushButton("▶ Start Live Capture")
        self.start_btn.setProperty("class", "SuccessBtn")
        self.start_btn.clicked.connect(self._start_live_capture)

        self.stop_btn = QPushButton("⏹ Stop Capture")
        self.stop_btn.setProperty("class", "DangerBtn")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self._stop_live_capture)

        btn_layout.addWidget(self.start_btn)
        btn_layout.addWidget(self.stop_btn)
        live_layout.addLayout(btn_layout)

        # Live capture status badge
        self.live_status_badge = QLabel("STATUS: IDLE")
        self.live_status_badge.setStyleSheet("color: #8b949e; font-weight: bold; font-size: 11px;")
        live_layout.addWidget(self.live_status_badge)

        top_panels.addWidget(live_card, stretch=5)

        # Right Panel: Offline PCAP File Analysis
        offline_card = QFrame()
        offline_card.setProperty("class", "CardFrame")
        off_layout = QVBoxLayout(offline_card)
        off_title = QLabel("Offline PCAP Forensic Analysis")
        off_title.setProperty("class", "SectionTitle")
        off_layout.addWidget(off_title)

        off_layout.addWidget(QLabel("Select PCAP / PCAPNG File:"))
        file_row = QHBoxLayout()
        self.pcap_file_input = QLineEdit()
        self.pcap_file_input.setPlaceholderText("Path to .pcap capture...")
        self.browse_pcap_btn = QPushButton("Browse...")
        self.browse_pcap_btn.clicked.connect(self._browse_pcap_file)
        self.sample_pcap_btn = QPushButton("Load Lab Sample")
        self.sample_pcap_btn.clicked.connect(self._load_sample_pcap)

        file_row.addWidget(self.pcap_file_input, stretch=3)
        file_row.addWidget(self.browse_pcap_btn, stretch=1)
        file_row.addWidget(self.sample_pcap_btn, stretch=1)
        off_layout.addLayout(file_row)

        self.analyze_pcap_btn = QPushButton("🔍 Analyze PCAP Traffic")
        self.analyze_pcap_btn.setProperty("class", "PrimaryBtn")
        self.analyze_pcap_btn.clicked.connect(self._analyze_selected_pcap)
        off_layout.addWidget(self.analyze_pcap_btn)

        self.pcap_progress = QProgressBar()
        self.pcap_progress.setRange(0, 0)
        self.pcap_progress.setVisible(False)
        off_layout.addWidget(self.pcap_progress)

        off_layout.addStretch()
        top_panels.addWidget(offline_card, stretch=5)

        layout.addLayout(top_panels)

        # 2. Metric Summary Cards
        metric_layout = QHBoxLayout()
        self.card_packets = self._create_metric_card("TOTAL PACKETS", "0", "#58a6ff")
        self.card_bytes = self._create_metric_card("TOTAL VOLUME", "0 B", "#3fb950")
        self.card_top_talker = self._create_metric_card("TOP TALKER (SRC IP)", "None", "#bc8cff")
        self.card_anomalies = self._create_metric_card("SECURITY ANOMALIES", "0", "#f85149")

        metric_layout.addWidget(self.card_packets)
        metric_layout.addWidget(self.card_bytes)
        metric_layout.addWidget(self.card_top_talker)
        metric_layout.addWidget(self.card_anomalies)
        layout.addLayout(metric_layout)

        # 3. Main Splitter: Tables (Top) & Live Capture Log (Bottom)
        splitter = QSplitter(Qt.Orientation.Vertical)

        # Sub-tabs for Forensic Tables
        self.tables_tab = QTabWidget()

        # Tab A: Top Talkers
        self.talkers_table = QTableWidget(0, 4)
        self.talkers_table.setHorizontalHeaderLabels([
            "Source IP Address", "Packet Count", "Byte Volume", "Traffic Share (%)"
        ])
        h_talk = self.talkers_table.horizontalHeader()
        h_talk.setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        h_talk.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        h_talk.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        h_talk.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.talkers_table.verticalHeader().setVisible(False)
        self.tables_tab.addTab(self.talkers_table, "📈 Top Talkers (Source IPs)")

        # Tab B: Protocol Breakdown
        self.proto_table = QTableWidget(0, 3)
        self.proto_table.setHorizontalHeaderLabels([
            "Protocol Layer", "Packet Count", "Distribution (%)"
        ])
        h_proto = self.proto_table.horizontalHeader()
        h_proto.setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        h_proto.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        h_proto.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.proto_table.verticalHeader().setVisible(False)
        self.tables_tab.addTab(self.proto_table, "📊 Protocol Distribution")

        # Tab C: Security Anomalies & Unusual Ports
        self.anomalies_table = QTableWidget(0, 4)
        self.anomalies_table.setHorizontalHeaderLabels([
            "Category", "Severity", "Target / Port", "Forensic Indicator Description"
        ])
        h_anom = self.anomalies_table.horizontalHeader()
        h_anom.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        h_anom.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        h_anom.setSectionResizeMode(2, QHeaderView.ResizeMode.Interactive)
        h_anom.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.anomalies_table.verticalHeader().setVisible(False)
        self.tables_tab.addTab(self.anomalies_table, "⚠️ Security Alerts & Unusual Ports")

        splitter.addWidget(self.tables_tab)

        # Bottom Stream Log
        log_card = QFrame()
        log_card.setProperty("class", "CardFrame")
        log_layout = QVBoxLayout(log_card)
        log_layout.addWidget(QLabel("Live Capture Stream & Diagnostic Log"))

        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setPlaceholderText("Tshark output and capture logs appear here...")
        log_layout.addWidget(self.log_view)

        splitter.addWidget(log_card)
        splitter.setSizes([280, 120])

        layout.addWidget(splitter, stretch=1)

        # Set default sample if exists
        sample_pcap = os.path.abspath("test_data/sample_traffic.pcap")
        if os.path.exists(sample_pcap):
            self.pcap_file_input.setText(sample_pcap)

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

    def _populate_interfaces(self):
        self.iface_combo.clear()
        interfaces = self.suite.get_network_interfaces()
        for iface in interfaces:
            label = f"{iface['name']} ({iface['description']})"
            self.iface_combo.addItem(label, iface["name"])

    def _update_timer(self):
        self._capture_seconds += 1
        m, s = divmod(self._capture_seconds, 60)
        self.live_status_badge.setText(f"STATUS: CAPTURING ({m:02d}:{s:02d})")
        self.live_status_badge.setStyleSheet("color: #3fb950; font-weight: bold; font-size: 11px;")

        # Auto stop if duration elapsed
        dur = self.duration_spin.value()
        if dur > 0 and self._capture_seconds >= dur:
            self._stop_live_capture()

    def _on_capture_line(self, line: str):
        """Thread-safe slot invoked on the GUI thread when a streaming line is received."""
        self.log_view.append(line)

    def _on_capture_finished(self, rc: int):
        """Thread-safe slot invoked on the GUI thread when the capture process terminates."""
        self.log_view.append(f"[+] Capture process exited (code {rc}).")

    def _start_live_capture(self):
        iface = self.iface_combo.currentData() or "lo"
        dur = self.duration_spin.value()
        bpf = self.bpf_input.text().strip() or None

        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self._capture_seconds = 0
        self._timer.start(1000)

        self.log_view.append(f"[*] Starting live packet capture on interface '{iface}'...")

        def _line_cb(line: str):
            # Emit via Qt signal to ensure GUI execution in main thread
            self.signal_bridge.line_received.emit(line)

        def _finished_cb(rc: int):
            self.signal_bridge.capture_finished.emit(rc)

        pcap_path, started = self.suite.start_packet_capture(
            interface=iface,
            duration=dur if dur > 0 else None,
            bpf_filter=bpf,
            line_callback=_line_cb,
            finished_callback=_finished_cb
        )

        if not started:
            self.log_view.append("[ERROR] Could not start capture process.")
            self._timer.stop()
            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            self.live_status_badge.setText("STATUS: ERROR")
            self.live_status_badge.setStyleSheet("color: #f85149; font-weight: bold; font-size: 11px;")
            return

        self._current_pcap = pcap_path
        self.pcap_file_input.setText(pcap_path)

    def _stop_live_capture(self):
        self._timer.stop()
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.live_status_badge.setText(f"STATUS: STOPPED ({self._capture_seconds}s)")
        self.live_status_badge.setStyleSheet("color: #8b949e; font-weight: bold; font-size: 11px;")

        pcap_path, rc = self.suite.stop_packet_capture()
        self.log_view.append(f"[+] Packet capture halted. Output saved to: {pcap_path}")

        # Automatically trigger analysis of captured file if exists and non-empty
        if pcap_path and os.path.exists(pcap_path) and os.path.getsize(pcap_path) > 0:
            self.pcap_file_input.setText(pcap_path)
            self._analyze_selected_pcap()

    def _browse_pcap_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select PCAP File",
            "workspace",
            "Packet Captures (*.pcap *.pcapng *.cap);;All Files (*)"
        )
        if path:
            self.pcap_file_input.setText(path)

    def _load_sample_pcap(self):
        sample_pcap = os.path.abspath("test_data/sample_traffic.pcap")
        if os.path.exists(sample_pcap):
            self.pcap_file_input.setText(sample_pcap)

    def _analyze_selected_pcap(self):
        pcap_path = self.pcap_file_input.text().strip()
        if not pcap_path or not os.path.isfile(pcap_path):
            self.log_view.append(f"[ERROR] Invalid PCAP file: {pcap_path}")
            return

        self.analyze_pcap_btn.setEnabled(False)
        self.pcap_progress.setVisible(True)
        self.log_view.append(f"[*] Analyzing packet capture: {os.path.basename(pcap_path)}...")

        self.analysis_worker = PcapAnalysisWorker(self.suite, pcap_path)
        self.analysis_worker.analysis_completed.connect(self._on_analysis_completed)
        self.analysis_worker.analysis_failed.connect(self._on_analysis_failed)
        self.analysis_worker.start()

    def _on_analysis_completed(self, result: Dict[str, Any]):
        self.analyze_pcap_btn.setEnabled(True)
        self.pcap_progress.setVisible(False)

        total_pkts = result.get("total_packets", 0)
        total_bytes = result.get("total_bytes", 0)
        talkers = result.get("top_talkers", [])
        protocols = result.get("protocols", {})
        unusual_ports = result.get("unusual_ports", [])
        anomalies = result.get("anomalies", [])

        # Update Metric Cards
        self.card_packets._lbl_val.setText(str(total_pkts))
        self.card_bytes._lbl_val.setText(self._format_bytes(total_bytes))
        top_ip = talkers[0]["ip"] if talkers else "None"
        self.card_top_talker._lbl_val.setText(top_ip)

        alert_count = len(anomalies) + len(unusual_ports)
        self.card_anomalies._lbl_val.setText(str(alert_count))
        self.card_anomalies._lbl_val.setStyleSheet(
            "color: #f85149;" if alert_count > 0 else "color: #3fb950;"
        )

        # 1. Populate Top Talkers
        self.talkers_table.setRowCount(0)
        for row_idx, t in enumerate(talkers):
            self.talkers_table.insertRow(row_idx)
            self.talkers_table.setItem(row_idx, 0, QTableWidgetItem(t["ip"]))
            self.talkers_table.setItem(row_idx, 1, QTableWidgetItem(str(t["packets"])))
            self.talkers_table.setItem(row_idx, 2, QTableWidgetItem(self._format_bytes(t["bytes"])))
            self.talkers_table.setItem(row_idx, 3, QTableWidgetItem(f"{t['percentage']}%"))

        # 2. Populate Protocols
        self.proto_table.setRowCount(0)
        for row_idx, (proto, meta) in enumerate(protocols.items()):
            self.proto_table.insertRow(row_idx)
            self.proto_table.setItem(row_idx, 0, QTableWidgetItem(proto))
            self.proto_table.setItem(row_idx, 1, QTableWidgetItem(str(meta["count"])))
            self.proto_table.setItem(row_idx, 2, QTableWidgetItem(f"{meta['percentage']}%"))

        # 3. Populate Anomalies & Unusual Ports
        self.anomalies_table.setRowCount(0)
        row_counter = 0

        for anom in anomalies:
            self.anomalies_table.insertRow(row_counter)
            self.anomalies_table.setItem(row_counter, 0, QTableWidgetItem("ANOMALY"))

            sev = anom.get("severity", "warning").upper()
            sev_item = QTableWidgetItem(sev)
            sev_item.setForeground(Qt.GlobalColor.red if sev == "CRITICAL" else Qt.GlobalColor.yellow)
            self.anomalies_table.setItem(row_counter, 1, sev_item)

            self.anomalies_table.setItem(row_counter, 2, QTableWidgetItem(anom.get("src_ip", "N/A")))
            self.anomalies_table.setItem(row_counter, 3, QTableWidgetItem(anom.get("description", "")))
            row_counter += 1

        for up in unusual_ports:
            self.anomalies_table.insertRow(row_counter)
            self.anomalies_table.setItem(row_counter, 0, QTableWidgetItem("UNUSUAL PORT"))

            sev = "WARNING" if up["port"] in (23, 21, 445, 3389) else "INFO"
            sev_item = QTableWidgetItem(sev)
            sev_item.setForeground(Qt.GlobalColor.yellow if sev == "WARNING" else Qt.GlobalColor.cyan)
            self.anomalies_table.setItem(row_counter, 1, sev_item)

            self.anomalies_table.setItem(row_counter, 2, QTableWidgetItem(f"Port {up['port']}/{up['proto']}"))
            self.anomalies_table.setItem(
                row_counter, 3,
                QTableWidgetItem(f"Observed {up['packet_count']} packets outside standard service allowlist.")
            )
            row_counter += 1

        self.log_view.append(f"[+] Forensic analysis complete: {total_pkts} packets parsed, {alert_count} alerts.")

    def _on_analysis_failed(self, error_msg: str):
        self.analyze_pcap_btn.setEnabled(True)
        self.pcap_progress.setVisible(False)
        self.log_view.append(f"[ERROR] Analysis failed:\n{error_msg}")

    @staticmethod
    def _format_bytes(num_bytes: int) -> str:
        for unit in ["B", "KB", "MB", "GB"]:
            if abs(num_bytes) < 1024.0:
                return f"{num_bytes:3.1f} {unit}"
            num_bytes /= 1024.0
        return f"{num_bytes:.1f} TB"

