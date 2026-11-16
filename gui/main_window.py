"""
gui/main_window.py - Main Window for Project ARGUS
Integrates all forensic modules under a unified dark SOC theme and ensures clean subprocess shutdown.
"""

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QCloseEvent
from PyQt6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QStatusBar,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from core.controller import ThreatForensicSuite
from gui.memory_tab import MemoryTab
from gui.packet_tab import PacketTab
from gui.scan_tab import ScanTab
from gui.styles import DARK_SOC_QSS
from gui.timeline_tab import TimelineTab


class MainWindow(QMainWindow):
    """
    Main SOC Dashboard Window for Project ARGUS.
    Houses the four forensic tabs and manages application lifecycle.
    """

    def __init__(self, suite: ThreatForensicSuite):
        super().__init__()
        self.suite = suite
        self.setWindowTitle("ARGUS — Cyber Threat & Forensic Analysis Suite")
        self.resize(1200, 850)
        self.setMinimumSize(950, 680)

        # Apply dark theme
        self.setStyleSheet(DARK_SOC_QSS)

        self._init_ui()

    def _init_ui(self):
        central_widget = QWidget()
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(16, 12, 16, 12)
        main_layout.setSpacing(10)

        # 1. Header Banner
        header_frame = QFrame()
        header_frame.setProperty("class", "CardFrame")
        h_layout = QHBoxLayout(header_frame)
        h_layout.setContentsMargins(12, 8, 12, 8)

        # Title & Subtitle
        title_vbox = QVBoxLayout()
        title_lbl = QLabel("ARGUS // CYBER THREAT & FORENSIC ANALYSIS SUITE")
        title_lbl.setProperty("class", "HeaderTitle")
        sub_lbl = QLabel("Unified SOC Dashboard  |  Kali Linux Platform  |  Author: Muhammad Inshal")
        sub_lbl.setProperty("class", "SubHeader")
        title_vbox.addWidget(title_lbl)
        title_vbox.addWidget(sub_lbl)
        h_layout.addLayout(title_vbox, stretch=4)

        # Status Pills
        pills_layout = QHBoxLayout()
        pills_layout.setSpacing(8)

        pill_guard = QLabel("🛡️ GUARDRAILS: ENFORCED")
        pill_guard.setStyleSheet(
            "background-color: #21262d; color: #3fb950; border: 1px solid #30363d; "
            "border-radius: 4px; padding: 4px 8px; font-weight: bold; font-size: 11px;"
        )
        pill_db = QLabel("🗄️ SQLITE: WAL MODE")
        pill_db.setStyleSheet(
            "background-color: #21262d; color: #58a6ff; border: 1px solid #30363d; "
            "border-radius: 4px; padding: 4px 8px; font-weight: bold; font-size: 11px;"
        )
        pill_legal = QLabel("⚖️ CC BY 4.0")
        pill_legal.setStyleSheet(
            "background-color: #21262d; color: #d29922; border: 1px solid #30363d; "
            "border-radius: 4px; padding: 4px 8px; font-weight: bold; font-size: 11px;"
        )

        pills_layout.addWidget(pill_guard)
        pills_layout.addWidget(pill_db)
        pills_layout.addWidget(pill_legal)
        h_layout.addLayout(pills_layout, stretch=3)

        main_layout.addWidget(header_frame)

        # 2. Main Tabs
        self.tabs = QTabWidget()
        self.packet_tab = PacketTab(self.suite)
        self.scan_tab = ScanTab(self.suite)
        self.memory_tab = MemoryTab(self.suite)
        self.timeline_tab = TimelineTab(self.suite)

        self.tabs.addTab(self.packet_tab, "📡 Packet Analyzer (tshark)")
        self.tabs.addTab(self.scan_tab, "🎯 Vulnerability Scanner (nmap)")
        self.tabs.addTab(self.memory_tab, "🧠 Memory Forensics (volatility3)")
        self.tabs.addTab(self.timeline_tab, "⏱️ Unified Timeline (Phase 6)")

        self.tabs.currentChanged.connect(self._on_tab_changed)
        main_layout.addWidget(self.tabs, stretch=1)

        self.setCentralWidget(central_widget)

        # 3. Status Bar
        self.status_bar = QStatusBar()
        self.status_bar.showMessage("ARGUS Security Suite ready. All forensic engines online.")
        self.setStatusBar(self.status_bar)

    def _on_tab_changed(self, index: int):
        # When switching to Unified Timeline tab, refresh timeline automatically
        if index == 3:
            self.timeline_tab.refresh_timeline()
            self.status_bar.showMessage("Unified chronological timeline refreshed.")

    def closeEvent(self, event: QCloseEvent):
        """
        Gracefully terminates subprocesses on exit to prevent orphaned processes.
        """
        self.status_bar.showMessage("Terminating active captures and cleaning up...")
        self.suite.shutdown()
        event.accept()
