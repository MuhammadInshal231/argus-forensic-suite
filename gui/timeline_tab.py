"""
gui/timeline_tab.py - Unified Chronological Forensic Timeline GUI Tab (Phase 6 Integration)
Correlates security findings across Packet Analyzer, Nmap Scanner, and Memory Forensics into a single story.
Features multi-parameter filtering, color-coded severity indicators, detail inspector, and JSON/CSV export.
"""

import json
import os
from typing import Any, Dict, List, Optional

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from core.controller import ThreatForensicSuite


class TimelineTab(QWidget):
    """PyQt6 tab for cross-module forensic event correlation and timeline export."""

    def __init__(self, suite: ThreatForensicSuite, parent=None):
        super().__init__(parent)
        self.suite = suite
        self._current_events: List[Dict[str, Any]] = []
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(16, 16, 16, 16)

        # 1. Filter & Search Toolbar Card
        filter_card = QFrame()
        filter_card.setProperty("class", "CardFrame")
        filter_layout = QHBoxLayout(filter_card)

        # Module Filter
        mod_vbox = QVBoxLayout()
        mod_vbox.addWidget(QLabel("Module Filter:"))
        self.module_combo = QComboBox()
        self.module_combo.addItem("All Modules", "all")
        self.module_combo.addItem("📡 Packet Analyzer", "packet")
        self.module_combo.addItem("🎯 Nmap Scanner", "scan")
        self.module_combo.addItem("🧠 Memory Forensics", "memory")
        self.module_combo.currentIndexChanged.connect(self.refresh_timeline)
        mod_vbox.addWidget(self.module_combo)
        filter_layout.addLayout(mod_vbox, stretch=2)

        # Severity Filter
        sev_vbox = QVBoxLayout()
        sev_vbox.addWidget(QLabel("Severity Filter:"))
        self.sev_combo = QComboBox()
        self.sev_combo.addItem("All Severities", "all")
        self.sev_combo.addItem("🔴 Critical Only", "critical")
        self.sev_combo.addItem("🟡 Warnings & Critical", "warning")
        self.sev_combo.addItem("🔵 Info Only", "info")
        self.sev_combo.currentIndexChanged.connect(self.refresh_timeline)
        sev_vbox.addWidget(self.sev_combo)
        filter_layout.addLayout(sev_vbox, stretch=2)

        # Keyword Search
        search_vbox = QVBoxLayout()
        search_vbox.addWidget(QLabel("Search Keywords:"))
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Filter events, IPs, ports, processes...")
        self.search_input.textChanged.connect(self.refresh_timeline)
        search_vbox.addWidget(self.search_input)
        filter_layout.addLayout(search_vbox, stretch=3)

        # Action Buttons
        btn_vbox = QVBoxLayout()
        btn_vbox.addWidget(QLabel("Actions:"))
        btn_row = QHBoxLayout()

        self.refresh_btn = QPushButton("🔄 Refresh")
        self.refresh_btn.clicked.connect(self.refresh_timeline)
        btn_row.addWidget(self.refresh_btn)

        self.export_btn = QPushButton("💾 Export Report")
        self.export_btn.setProperty("class", "PrimaryBtn")
        self.export_btn.clicked.connect(self._export_report)
        btn_row.addWidget(self.export_btn)

        btn_vbox.addLayout(btn_row)
        filter_layout.addLayout(btn_vbox, stretch=3)

        layout.addWidget(filter_card)

        # 2. Metric Summary Cards
        metric_layout = QHBoxLayout()
        self.card_total = self._create_metric_card("CORRELATED EVENTS", "0", "#58a6ff")
        self.card_crit = self._create_metric_card("CRITICAL ALERTS", "0", "#f85149")
        self.card_warn = self._create_metric_card("WARNINGS", "0", "#d29922")
        self.card_info = self._create_metric_card("INFORMATIONAL", "0", "#79c0ff")

        metric_layout.addWidget(self.card_total)
        metric_layout.addWidget(self.card_crit)
        metric_layout.addWidget(self.card_warn)
        metric_layout.addWidget(self.card_info)
        layout.addLayout(metric_layout)

        # 3. Splitter: Chronological Table (Top) & Detail Inspector (Bottom)
        splitter = QSplitter(Qt.Orientation.Vertical)

        # Events Table Card
        table_card = QFrame()
        table_card.setProperty("class", "CardFrame")
        table_layout = QVBoxLayout(table_card)
        table_layout.addWidget(QLabel("Unified Multi-Engine Security Event Feed"))

        self.timeline_table = QTableWidget(0, 6)
        self.timeline_table.setHorizontalHeaderLabels([
            "ID", "Timestamp (UTC)", "Engine", "Severity", "Event Type", "Forensic Summary"
        ])
        h_table = self.timeline_table.horizontalHeader()
        h_table.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        h_table.setSectionResizeMode(1, QHeaderView.ResizeMode.Interactive)
        h_table.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        h_table.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        h_table.setSectionResizeMode(4, QHeaderView.ResizeMode.Interactive)
        h_table.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        self.timeline_table.verticalHeader().setVisible(False)
        self.timeline_table.itemSelectionChanged.connect(self._on_event_selected)
        table_layout.addWidget(self.timeline_table)

        splitter.addWidget(table_card)

        # Detail Inspector Card
        detail_card = QFrame()
        detail_card.setProperty("class", "CardFrame")
        detail_layout = QVBoxLayout(detail_card)
        detail_layout.addWidget(QLabel("Forensic Event Inspector & Evidence Payload"))

        self.detail_view = QTextEdit()
        self.detail_view.setReadOnly(True)
        self.detail_view.setPlaceholderText("Select any timeline row to inspect full JSON metadata and forensic context...")
        detail_layout.addWidget(self.detail_view)

        splitter.addWidget(detail_card)
        splitter.setSizes([340, 160])

        layout.addWidget(splitter, stretch=1)

        # Initial data load
        self.refresh_timeline()

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

    def refresh_timeline(self, *args):
        mod = self.module_combo.currentData()
        sev = self.sev_combo.currentData()
        query_text = self.search_input.text().strip() or None

        events = self.suite.get_timeline(
            module=mod if mod != "all" else None,
            severity=sev if sev != "all" else None,
            search=query_text
        )
        self._current_events = events

        # Compute stats
        stats = self.suite.get_statistics()
        by_sev = stats.get("by_severity", {})
        self.card_total._lbl_val.setText(str(len(events)))
        self.card_crit._lbl_val.setText(str(by_sev.get("critical", 0)))
        self.card_warn._lbl_val.setText(str(by_sev.get("warning", 0)))
        self.card_info._lbl_val.setText(str(by_sev.get("info", 0)))

        # Populate Table
        self.timeline_table.setRowCount(0)
        for row_idx, ev in enumerate(events):
            self.timeline_table.insertRow(row_idx)

            self.timeline_table.setItem(row_idx, 0, QTableWidgetItem(str(ev["id"])))
            self.timeline_table.setItem(row_idx, 1, QTableWidgetItem(ev["timestamp"]))

            # Module icon & badge
            mod_name = ev["module"]
            mod_icon = "📡 Packet" if mod_name == "packet" else ("🎯 Scan" if mod_name == "scan" else "🧠 Memory")
            self.timeline_table.setItem(row_idx, 2, QTableWidgetItem(mod_icon))

            # Severity badge with color
            severity = (ev.get("severity") or "info").upper()
            sev_item = QTableWidgetItem(severity)
            if severity == "CRITICAL":
                sev_item.setForeground(Qt.GlobalColor.red)
            elif severity == "WARNING":
                sev_item.setForeground(Qt.GlobalColor.yellow)
            else:
                sev_item.setForeground(Qt.GlobalColor.cyan)
            self.timeline_table.setItem(row_idx, 3, sev_item)

            self.timeline_table.setItem(row_idx, 4, QTableWidgetItem(ev["event_type"]))

            # Summary snippet
            summary_snippet = self._build_summary_snippet(ev)
            self.timeline_table.setItem(row_idx, 5, QTableWidgetItem(summary_snippet))

        if events:
            self.timeline_table.selectRow(0)

    def _build_summary_snippet(self, event: Dict[str, Any]) -> str:
        d = event.get("details", {})
        if not isinstance(d, dict):
            return str(d)[:80]

        ev_type = event.get("event_type", "")
        if ev_type == "open_port":
            return f"Port {d.get('port')}/{d.get('protocol')} open: {d.get('service')} {d.get('version', '')} - {d.get('risk_assessment', '')}"
        elif ev_type == "host_scan_completed":
            return f"Nmap completed on {d.get('target')}: {d.get('open_ports')} open ports, {d.get('risky_services')} risky services."
        elif ev_type == "pcap_analysis_completed":
            return f"PCAP '{d.get('pcap_file')}': {d.get('total_packets')} pkts, top talker {d.get('top_talker')}."
        elif ev_type == "port_scan_detected":
            return f"Port sweep alert from {d.get('src_ip')}: targeted {len(d.get('targeted_ports', []))} ports."
        elif ev_type == "unencrypted_http":
            return f"Cleartext HTTP alert: {d.get('description')} ({d.get('src_ip')} -> {d.get('dst_ip')})"
        elif ev_type == "dump_analysis_completed":
            return f"Memory dump '{d.get('dump_file')}': {d.get('process_count')} procs, {d.get('malfind_hits')} code injections."
        elif "memory" in ev_type:
            return f"{d.get('title', '')}: {d.get('details', '')}"

        return json.dumps(d)[:90]

    def _on_event_selected(self):
        row = self.timeline_table.currentRow()
        if 0 <= row < len(self._current_events):
            ev = self._current_events[row]
            header = (
                f"======================================================================\n"
                f"EVENT #{ev['id']}  |  TIMESTAMP (UTC): {ev['timestamp']}\n"
                f"ENGINE: {ev['module'].upper()}  |  SEVERITY: {str(ev['severity']).upper()}  |  TYPE: {ev['event_type']}\n"
                f"======================================================================\n\n"
            )
            details = ev.get("details")
            if isinstance(details, (dict, list)):
                formatted_json = json.dumps(details, indent=2)
            else:
                formatted_json = str(details)

            context_help = self._generate_context_guidance(ev)
            self.detail_view.setText(f"{header}{formatted_json}\n\n{context_help}")

    def _generate_context_guidance(self, event: Dict[str, Any]) -> str:
        ev_type = event.get("event_type", "")
        sev = (event.get("severity") or "").lower()

        if sev == "critical":
            return (
                "--- FORENSIC TRIAGE ADVICE ---\n"
                "[CRITICAL ALERT] Immediate investigation recommended. Correlate memory injected addresses "
                "with network sockets and process command lines. Review surrounding pcap packets for active C2."
            )
        elif sev == "warning":
            return (
                "--- FORENSIC TRIAGE ADVICE ---\n"
                "[WARNING] Insecure protocol or unusual port identified. Verify service authorization "
                "against corporate asset baseline and evaluate firewall filtering rules."
            )
        return "--- FORENSIC NOTE ---\nRoutine forensic artifact successfully indexed into unified investigation database."

    def _export_report(self):
        file_path, selected_filter = QFileDialog.getSaveFileName(
            self,
            "Export Forensic Investigation Timeline",
            "workspace/argus_forensic_report.json",
            "JSON Report (*.json);;CSV Report (*.csv)"
        )
        if not file_path:
            return

        fmt = "csv" if file_path.endswith(".csv") or "CSV" in selected_filter else "json"
        try:
            saved_file = self.suite.export_report(
                output_filepath=file_path,
                format_type=fmt,
                module=self.module_combo.currentData() if self.module_combo.currentData() != "all" else None,
                severity=self.sev_combo.currentData() if self.sev_combo.currentData() != "all" else None
            )
            QMessageBox.information(
                self,
                "Report Exported",
                f"Forensic timeline successfully exported to:\n{saved_file}"
            )
        except Exception as exc:
            QMessageBox.critical(self, "Export Error", f"Failed to export timeline report:\n{exc}")

