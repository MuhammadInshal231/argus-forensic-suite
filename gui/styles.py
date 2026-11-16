"""
gui/styles.py - Dark-Themed SOC Cybersecurity QSS Stylesheet
Provides consistent styling across all ARGUS tabs, controls, and tables.
"""

DARK_SOC_QSS = """
/* Global Window & Fonts */
QWidget {
    background-color: #0d1117;
    color: #e6edf3;
    font-family: "DejaVu Sans", "Segoe UI", Arial, sans-serif;
    font-size: 13px;
    selection-background-color: #1f6feb;
    selection-color: #ffffff;
}

/* Main Window */
QMainWindow {
    background-color: #090d13;
}

/* Header & Panels */
QFrame.CardFrame {
    background-color: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 12px;
}

QFrame.MetricCard {
    background-color: #161b22;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 8px;
}

/* Headers */
QLabel.HeaderTitle {
    font-size: 20px;
    font-weight: bold;
    color: #58a6ff;
    letter-spacing: 1px;
}

QLabel.SubHeader {
    font-size: 12px;
    color: #8b949e;
}

QLabel.SectionTitle {
    font-size: 14px;
    font-weight: bold;
    color: #79c0ff;
    margin-bottom: 4px;
}

QLabel.MetricValue {
    font-size: 22px;
    font-weight: bold;
    color: #58a6ff;
}

QLabel.MetricLabel {
    font-size: 11px;
    color: #8b949e;
    text-transform: uppercase;
}

/* Tab Widget & Bars */
QTabWidget::pane {
    border: 1px solid #30363d;
    border-radius: 6px;
    background-color: #0d1117;
    top: -1px;
}

QTabBar::tab {
    background-color: #161b22;
    color: #8b949e;
    border: 1px solid #30363d;
    border-bottom: none;
    padding: 10px 20px;
    margin-right: 4px;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
    font-weight: 600;
}

QTabBar::tab:selected {
    background-color: #0d1117;
    color: #58a6ff;
    border-bottom: 2px solid #58a6ff;
}

QTabBar::tab:hover:!selected {
    background-color: #21262d;
    color: #c9d1d9;
}

/* Inputs & Combos */
QLineEdit, QComboBox, QSpinBox {
    background-color: #090d13;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 6px 10px;
    color: #e6edf3;
    font-family: "DejaVu Sans Mono", monospace;
    font-size: 12px;
}

QLineEdit:focus, QComboBox:focus, QSpinBox:focus {
    border: 1px solid #58a6ff;
}

QComboBox::drop-down {
    subcontrol-origin: padding;
    subcontrol-position: top right;
    width: 24px;
    border-left: 1px solid #30363d;
}

QComboBox QAbstractItemView {
    background-color: #161b22;
    border: 1px solid #30363d;
    color: #e6edf3;
    selection-background-color: #1f6feb;
}

/* Buttons */
QPushButton {
    background-color: #21262d;
    border: 1px solid #363b42;
    border-radius: 6px;
    padding: 7px 16px;
    color: #c9d1d9;
    font-weight: 600;
}

QPushButton:hover {
    background-color: #30363d;
    border-color: #8b949e;
    color: #ffffff;
}

QPushButton:pressed {
    background-color: #161b22;
}

QPushButton:disabled {
    background-color: #161b22;
    border-color: #21262d;
    color: #484f58;
}

/* Accent Buttons */
QPushButton.PrimaryBtn {
    background-color: #1f6feb;
    border: 1px solid #388bfd;
    color: #ffffff;
}

QPushButton.PrimaryBtn:hover {
    background-color: #388bfd;
}

QPushButton.SuccessBtn {
    background-color: #238636;
    border: 1px solid #2ea043;
    color: #ffffff;
}

QPushButton.SuccessBtn:hover {
    background-color: #2ea043;
}

QPushButton.DangerBtn {
    background-color: #da3633;
    border: 1px solid #f85149;
    color: #ffffff;
}

QPushButton.DangerBtn:hover {
    background-color: #f85149;
}

/* Tables */
QTableWidget, QTreeWidget {
    background-color: #090d13;
    border: 1px solid #30363d;
    border-radius: 6px;
    gridline-color: #21262d;
    color: #e6edf3;
    font-family: "DejaVu Sans Mono", monospace;
    font-size: 12px;
}

QTableWidget::item, QTreeWidget::item {
    padding: 6px;
}

QTableWidget::item:selected, QTreeWidget::item:selected {
    background-color: #1f6feb;
    color: #ffffff;
}

QHeaderView::section {
    background-color: #161b22;
    color: #8b949e;
    font-size: 11px;
    font-weight: bold;
    border: none;
    border-right: 1px solid #21262d;
    border-bottom: 1px solid #30363d;
    padding: 6px 8px;
    text-transform: uppercase;
}

/* Text & Console Views */
QTextEdit, QPlainTextEdit {
    background-color: #090d13;
    border: 1px solid #30363d;
    border-radius: 6px;
    color: #7ee787;
    font-family: "DejaVu Sans Mono", monospace;
    font-size: 11px;
    padding: 8px;
}

/* Progress Bars */
QProgressBar {
    background-color: #161b22;
    border: 1px solid #30363d;
    border-radius: 4px;
    text-align: center;
    color: #ffffff;
    font-size: 11px;
    font-weight: bold;
}

QProgressBar::chunk {
    background-color: #238636;
    border-radius: 3px;
}

/* Scrollbars */
QScrollBar:vertical {
    background: #0d1117;
    width: 10px;
    margin: 0px;
}

QScrollBar::handle:vertical {
    background: #30363d;
    min-height: 20px;
    border-radius: 5px;
}

QScrollBar::handle:vertical:hover {
    background: #8b949e;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}

/* Status Bar */
QStatusBar {
    background-color: #161b22;
    border-top: 1px solid #30363d;
    color: #8b949e;
    font-size: 12px;
}
"""
