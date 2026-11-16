"""
gui/memory_tab.py - Memory Forensics GUI Tab (volatility3 orchestrator)
Features RAM dump inspection, process lists, network sockets, and malfind code injection analysis.
"""

import os
from typing import Any, Dict, Optional

from PyQt6.QtCore import QThread, pyqtSignal, Qt
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
    QSplitter,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from core.controller import ThreatForensicSuite


class MemoryWorker(QThread):
    """Asynchronous background worker for executing Volatility 3 plugins."""
    analysis_completed = pyqtSignal(dict)
    analysis_failed = pyqtSignal(str)

    def __init__(self, suite: ThreatForensicSuite, dump_path: str, os_type: str):
        super().__init__()
        self.suite = suite
        self.dump_path = dump_path
        self.os_type = os_type

    def run(self):
        try:
            result = self.suite.analyze_memory_dump(self.dump_path, self.os_type)
            if result.get("success"):
                self.analysis_completed.emit(result)
            else:
                self.analysis_failed.emit(result.get("error", "Memory analysis failed."))
        except Exception as exc:
            self.analysis_failed.emit(str(exc))


class MemoryTab(QWidget):
    """PyQt6 tab for memory forensics and volatility plugin inspection."""

    def __init__(self, suite: ThreatForensicSuite, parent=None):
        super().__init__(parent)
        self.suite = suite
        self.worker: Optional[MemoryWorker] = None
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(16, 16, 16, 16)

        # 1. Target Controls Card
        ctrl_card = QFrame()
        ctrl_card.setProperty("class", "CardFrame")
        ctrl_layout = QVBoxLayout(ctrl_card)

        title = QLabel("RAM Memory Dump Analysis (Volatility 3)")
        title.setProperty("class", "SectionTitle")
        ctrl_layout.addWidget(title)

        inputs_layout = QHBoxLayout()

        # File path
        file_vbox = QVBoxLayout()
        file_vbox.addWidget(QLabel("Memory Dump File (.raw, .mem, .vmem, .dmp, .forensic):"))
        file_h_layout = QHBoxLayout()
        self.file_input = QLineEdit()
        self.file_input.setPlaceholderText("Select or browse for a memory image...")
        self.browse_btn = QPushButton("Browse...")
        self.browse_btn.clicked.connect(self._browse_dump_file)
        self.sample_btn = QPushButton("Load Lab Sample")
        self.sample_btn.clicked.connect(self._load_sample_dump)

        file_h_layout.addWidget(self.file_input, stretch=4)
        file_h_layout.addWidget(self.browse_btn, stretch=1)
        file_h_layout.addWidget(self.sample_btn, stretch=1)
        file_vbox.addLayout(file_h_layout)
        inputs_layout.addLayout(file_vbox, stretch=5)

        # OS Type Dropdown
        os_vbox = QVBoxLayout()
        os_vbox.addWidget(QLabel("OS Architecture:"))
        self.os_combo = QComboBox()
        self.os_combo.addItem("Windows (windows.*)", "windows")
        self.os_combo.addItem("Linux (linux.*)", "linux")
        os_vbox.addWidget(self.os_combo)
        inputs_layout.addLayout(os_vbox, stretch=2)

        # Analyze Button
        btn_vbox = QVBoxLayout()
        btn_vbox.addWidget(QLabel("Action:"))
        self.analyze_btn = QPushButton("🧠 Run Memory Forensics")
        self.analyze_btn.setProperty("class", "PrimaryBtn")
        self.analyze_btn.clicked.connect(self._start_analysis)
        btn_vbox.addWidget(self.analyze_btn)
        inputs_layout.addLayout(btn_vbox, stretch=2)

        ctrl_layout.addLayout(inputs_layout)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0)
        self.progress_bar.setVisible(False)
        ctrl_layout.addWidget(self.progress_bar)

        layout.addWidget(ctrl_card)

        # 2. Metric Summary Cards
        metric_layout = QHBoxLayout()
        self.card_file = self._create_metric_card("TARGET DUMP", "None", "#8b949e")
        self.card_procs = self._create_metric_card("ACTIVE PROCESSES", "0", "#58a6ff")
        self.card_sockets = self._create_metric_card("SOCKETS (NETSCAN)", "0", "#3fb950")
        self.card_malfind = self._create_metric_card("MALFIND INJECTIONS", "0", "#f85149")

        metric_layout.addWidget(self.card_file)
        metric_layout.addWidget(self.card_procs)
        metric_layout.addWidget(self.card_sockets)
        metric_layout.addWidget(self.card_malfind)
        layout.addLayout(metric_layout)

        # 3. Sub-Tabbed Forensic Views
        self.sub_tabs = QTabWidget()

        # Tab A: Process List
        self.proc_table = QTableWidget(0, 6)
        self.proc_table.setHorizontalHeaderLabels([
            "PID", "PPID", "Process Name", "Creation Time (UTC)", "Threads", "Security Flags"
        ])
        h_proc = self.proc_table.horizontalHeader()
        h_proc.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        h_proc.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        h_proc.setSectionResizeMode(2, QHeaderView.ResizeMode.Interactive)
        h_proc.setSectionResizeMode(3, QHeaderView.ResizeMode.Interactive)
        h_proc.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        h_proc.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        self.proc_table.verticalHeader().setVisible(False)
        self.sub_tabs.addTab(self.proc_table, "📊 Process Tree (pslist)")

        # Tab B: Network Sockets
        self.net_table = QTableWidget(0, 7)
        self.net_table.setHorizontalHeaderLabels([
            "Proto", "Local Address:Port", "Foreign Address:Port", "State", "PID", "Owner Process", "Risk Flag"
        ])
        h_net = self.net_table.horizontalHeader()
        h_net.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        h_net.setSectionResizeMode(1, QHeaderView.ResizeMode.Interactive)
        h_net.setSectionResizeMode(2, QHeaderView.ResizeMode.Interactive)
        h_net.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        h_net.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        h_net.setSectionResizeMode(5, QHeaderView.ResizeMode.Interactive)
        h_net.setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)
        self.net_table.verticalHeader().setVisible(False)
        self.sub_tabs.addTab(self.net_table, "🌐 Sockets & Connections (netscan)")

        # Tab C: Code Injections (malfind)
        malfind_widget = QWidget()
        mal_vbox = QVBoxLayout(malfind_widget)
        mal_vbox.setContentsMargins(8, 8, 8, 8)

        self.malfind_table = QTableWidget(0, 5)
        self.malfind_table.setHorizontalHeaderLabels([
            "PID", "Process Name", "Start Address", "Memory Protection", "Injection Summary"
        ])
        h_mal = self.malfind_table.horizontalHeader()
        h_mal.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        h_mal.setSectionResizeMode(1, QHeaderView.ResizeMode.Interactive)
        h_mal.setSectionResizeMode(2, QHeaderView.ResizeMode.Interactive)
        h_mal.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        h_mal.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.malfind_table.verticalHeader().setVisible(False)
        self.malfind_table.itemSelectionChanged.connect(self._on_malfind_selected)
        mal_vbox.addWidget(self.malfind_table, stretch=2)

        mal_vbox.addWidget(QLabel("Disassembly & Hex Preview of Injected Buffer:"))
        self.malfind_preview = QTextEdit()
        self.malfind_preview.setReadOnly(True)
        self.malfind_preview.setPlaceholderText("Select an injected memory region above to view disassembly...")
        mal_vbox.addWidget(self.malfind_preview, stretch=1)

        self.sub_tabs.addTab(malfind_widget, "⚠️ Code Injections (malfind)")

        layout.addWidget(self.sub_tabs, stretch=1)

        # Set default to sample dump if exists
        sample_path = os.path.abspath("test_data/sample_memory.forensic")
        if os.path.exists(sample_path):
            self.file_input.setText(sample_path)
            self.card_file._lbl_val.setText(os.path.basename(sample_path))

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

    def _browse_dump_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Memory Dump",
            "test_data",
            "Memory Dumps (*.raw *.mem *.vmem *.dmp *.forensic *.sav);;All Files (*)"
        )
        if file_path:
            self.file_input.setText(file_path)
            self.card_file._lbl_val.setText(os.path.basename(file_path))

    def _load_sample_dump(self):
        sample_path = os.path.abspath("test_data/sample_memory.forensic")
        if os.path.exists(sample_path):
            self.file_input.setText(sample_path)
            self.card_file._lbl_val.setText(os.path.basename(sample_path))

    def _start_analysis(self):
        dump_path = self.file_input.text().strip()
        if not dump_path or not os.path.isfile(dump_path):
            self.malfind_preview.setText(f"[ERROR] Invalid or nonexistent memory dump file: {dump_path}")
            return

        os_type = self.os_combo.currentData()
        self.analyze_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.card_file._lbl_val.setText(os.path.basename(dump_path))
        self.card_procs._lbl_val.setText("ANALYZING...")

        self.worker = MemoryWorker(self.suite, dump_path, os_type)
        self.worker.analysis_completed.connect(self._on_analysis_completed)
        self.worker.analysis_failed.connect(self._on_analysis_failed)
        self.worker.start()

    def _on_analysis_completed(self, result: Dict[str, Any]):
        self.analyze_btn.setEnabled(True)
        self.progress_bar.setVisible(False)

        processes = result.get("processes", [])
        connections = result.get("connections", [])
        malfind_hits = result.get("malfind_hits", [])

        # Update Metric Cards
        self.card_procs._lbl_val.setText(str(len(processes)))
        self.card_sockets._lbl_val.setText(str(len(connections)))
        self.card_malfind._lbl_val.setText(str(len(malfind_hits)))
        self.card_malfind._lbl_val.setStyleSheet(
            "color: #f85149;" if len(malfind_hits) > 0 else "color: #3fb950;"
        )

        # 1. Populate Processes
        self.proc_table.setRowCount(0)
        for row_idx, p in enumerate(processes):
            self.proc_table.insertRow(row_idx)
            self.proc_table.setItem(row_idx, 0, QTableWidgetItem(str(p["pid"])))
            self.proc_table.setItem(row_idx, 1, QTableWidgetItem(str(p["ppid"])))
            self.proc_table.setItem(row_idx, 2, QTableWidgetItem(p["name"]))
            self.proc_table.setItem(row_idx, 3, QTableWidgetItem(p["create_time"]))
            self.proc_table.setItem(row_idx, 4, QTableWidgetItem(str(p["threads"])))

            pname_lower = p["name"].lower()
            if "mimikatz" in pname_lower or "meterpreter" in pname_lower:
                flag_item = QTableWidgetItem("CRITICAL: Known Hacktool")
                flag_item.setForeground(Qt.GlobalColor.red)
            elif "cmd.exe" in pname_lower or "powershell" in pname_lower:
                flag_item = QTableWidgetItem("WARNING: Shell Execution")
                flag_item.setForeground(Qt.GlobalColor.yellow)
            else:
                flag_item = QTableWidgetItem("Normal System Process")
                flag_item.setForeground(Qt.GlobalColor.gray)
            self.proc_table.setItem(row_idx, 5, flag_item)

        # 2. Populate Sockets
        self.net_table.setRowCount(0)
        for row_idx, c in enumerate(connections):
            self.net_table.insertRow(row_idx)
            self.net_table.setItem(row_idx, 0, QTableWidgetItem(c["proto"]))
            self.net_table.setItem(row_idx, 1, QTableWidgetItem(f"{c['local_addr']}:{c['local_port']}"))
            self.net_table.setItem(row_idx, 2, QTableWidgetItem(f"{c['foreign_addr']}:{c['foreign_port']}"))
            self.net_table.setItem(row_idx, 3, QTableWidgetItem(c["state"]))
            self.net_table.setItem(row_idx, 4, QTableWidgetItem(str(c["pid"])))
            self.net_table.setItem(row_idx, 5, QTableWidgetItem(c["owner"]))

            risk_flag = "Normal"
            f_port = c.get("foreign_port")
            if f_port in (4444, 1337, 8888):
                risk_flag = f"WARNING: Suspicious Port {f_port}"
                risk_item = QTableWidgetItem(risk_flag)
                risk_item.setForeground(Qt.GlobalColor.red)
            else:
                risk_item = QTableWidgetItem("Authorized Lab Traffic")
                risk_item.setForeground(Qt.GlobalColor.gray)
            self.net_table.setItem(row_idx, 6, risk_item)

        # 3. Populate Malfind
        self.malfind_table.setRowCount(0)
        self._current_malfind = malfind_hits
        for row_idx, m in enumerate(malfind_hits):
            self.malfind_table.insertRow(row_idx)
            self.malfind_table.setItem(row_idx, 0, QTableWidgetItem(str(m["pid"])))
            self.malfind_table.setItem(row_idx, 1, QTableWidgetItem(m["process_name"]))
            self.malfind_table.setItem(row_idx, 2, QTableWidgetItem(m["start_address"]))

            prot_item = QTableWidgetItem(m["protection"])
            if "EXECUTE_READWRITE" in m["protection"]:
                prot_item.setForeground(Qt.GlobalColor.red)
            self.malfind_table.setItem(row_idx, 3, prot_item)

            summary_item = QTableWidgetItem("CRITICAL: Unbacked executable RWX segment (Injected Payload)")
            summary_item.setForeground(Qt.GlobalColor.red)
            self.malfind_table.setItem(row_idx, 4, summary_item)

        if malfind_hits:
            self.sub_tabs.setCurrentIndex(2)  # Focus Malfind if injections found
            self.malfind_table.selectRow(0)

    def _on_malfind_selected(self):
        selected_rows = self.malfind_table.selectedItems()
        if not selected_rows or not hasattr(self, "_current_malfind"):
            return

        row_idx = self.malfind_table.currentRow()
        if 0 <= row_idx < len(self._current_malfind):
            m = self._current_malfind[row_idx]
            text = (
                f"[MALFIND FORENSIC INSPECTION]\n"
                f"Target Process: {m.get('process_name')} (PID: {m.get('pid')})\n"
                f"Memory Range: {m.get('start_address')} - {m.get('end_address')}\n"
                f"Page Protection: {m.get('protection')}\n\n"
                f"--- Disassembly ---\n{m.get('disassembly', 'N/A')}\n\n"
                f"--- Hex Dump ---\n{m.get('hexdump', 'N/A')}\n"
            )
            self.malfind_preview.setText(text)

    def _on_analysis_failed(self, error_msg: str):
        self.analyze_btn.setEnabled(True)
        self.progress_bar.setVisible(False)
        self.card_procs._lbl_val.setText("ERROR")
        self.malfind_preview.setText(f"[ERROR] Memory forensics analysis failed:\n{error_msg}")
