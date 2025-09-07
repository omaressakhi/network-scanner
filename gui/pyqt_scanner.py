# pyqt_scanner.py
# pip install PyQt6

import sys
import socket
import threading
from PyQt6.QtCore import Qt, QObject, QThread, pyqtSignal
from PyQt6.QtWidgets import (
    QApplication, QWidget, QPushButton, QLabel, QLineEdit, QVBoxLayout,
    QGridLayout, QMessageBox, QStackedWidget, QTableWidget,
    QTableWidgetItem, QHeaderView
)

# functions from your scanner.py
from scanner import scan, get_mac, resolve_mac_vendor, is_host_reachable

# --- Multi-threaded socket scan ---
def scan_ports_gui(host, ports):
    open_ports = []

    def scan_single(port):
        try:
            s = socket.socket()

            s.settimeout(1)
            if s.connect_ex((host, port)) == 0:
                open_ports.append((port, "open"))
            s.close()
        except:
            pass

    threads = []
    for p in ports:
        t = threading.Thread(target=scan_single, args=(p,))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    return open_ports

# -------- Worker --------
class Worker(QObject):
    finished = pyqtSignal(list)
    error = pyqtSignal(str)

    def __init__(self, action: str, arg1: str = "", arg2: str = ""):
        super().__init__()
        self.action = action
        self.arg1 = arg1
        self.arg2 = arg2

    def run(self):
        try:
            if self.action == "network":
                network = self.arg1
                clients = scan(network)
                rows = []
                for c in clients:
                    mac = c.get('mac', '')
                    vendor = resolve_mac_vendor(mac)
                    rows.append((c.get('ip', ''), mac, vendor))
                self.finished.emit(rows)

            elif self.action == "os":
                ip = self.arg1
                mac = get_mac(ip)
                vendor = resolve_mac_vendor(mac)
                self.finished.emit([(ip, mac, vendor)])

            elif self.action == "top":
                ip = self.arg1
                ports = scan_ports_gui(ip, range(1, 1025))
                rows = [(ip, f"Port {p[0]} {p[1]}:::fuy", "") for p in ports]
                self.finished.emit(rows)

            elif self.action == "range":
                ip = self.arg1
                start_p, end_p = map(int, self.arg2.split("-"))
                ports = scan_ports_gui(ip, range(start_p, end_p + 1))
                rows = [(ip, f"Port {p[0]} {p[1]}", "") for p in ports]
                self.finished.emit(rows)

            elif self.action == "all":
                ip = self.arg1
                ports = scan_ports_gui(ip, range(1, 65536))
                rows = [(ip, f"Port {p[0]} {p[1]}", "") for p in ports]
                self.finished.emit(rows)

            elif self.action == "host":
                ip = self.arg1
                reachable = is_host_reachable(ip)
                print(f"[DEBUG][GUI] is_host_reachable({ip}) returned: {reachable}")
                status = "UP" if reachable else "DOWN"
                self.finished.emit([(ip, status, "")])

            else:
                self.error.emit("Unknown action")

        except Exception as e:
            self.error.emit(str(e))

# -------- Styles --------
BTN_STYLE_GREEN = """
QPushButton {
    background-color: #2E8B57;
    color: white;
    font-weight: bold;
    border-radius: 8px;
    padding: 8px;
}
QPushButton:hover {
    background-color: #2E8B57;
}
"""

BTN_STYLE_RED = """
QPushButton {
    background-color: #C0392B;
    color: white;
    font-weight: bold;
    border-radius: 8px;
    padding: 8px;
}
QPushButton:hover {
    background-color: #C0392B;
}
"""

# -------- Pages --------
class Page1(QWidget):
    go_next = pyqtSignal()

    def __init__(self):
        super().__init__()
        self.setStyleSheet("background-color: black; color: white;")
        layout = QVBoxLayout(self)
        layout.addStretch(1)
        btn = QPushButton("Scanner")
        btn.setStyleSheet(BTN_STYLE_GREEN)
        btn.setMinimumHeight(60)
        btn.clicked.connect(self.go_next.emit)
        layout.addWidget(btn, alignment=Qt.AlignmentFlag.AlignCenter)
        layout.addStretch(1)

class Page2(QWidget):
    choose_action = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.setStyleSheet("background-color: black; color: white;")
        layout = QVBoxLayout(self)
        title = QLabel("اختار نوع الـ Scan")
        title = QLabel("Choose the type of Scan")
        title.setStyleSheet("font-size: 18px; font-weight: 600; color: white;")
        layout.addWidget(title, alignment=Qt.AlignmentFlag.AlignHCenter)

        grid = QGridLayout()
        buttons = [
            ("Scan Network", "network"),
            ("OS / MAC Detection", "os"),
            ("Scan Top Ports", "top"),
            ("Scan Port Range", "range"),
            ("Scan All Ports", "all"),
            ("Check Host Reachable", "host"),
        ]
        for i, (text, key) in enumerate(buttons):
            b = QPushButton(text)
            b.setStyleSheet(BTN_STYLE_GREEN)
            b.setMinimumHeight(40)
            b.clicked.connect(lambda _, k=key: self.choose_action.emit(k))
            grid.addWidget(b, i // 2, i % 2)

        layout.addLayout(grid)

        self.back_btn = QPushButton("Back")
        self.back_btn.setStyleSheet(BTN_STYLE_RED)
        layout.addWidget(self.back_btn, alignment=Qt.AlignmentFlag.AlignLeft)

class Page3(QWidget):
    back = pyqtSignal()

    def __init__(self):
        super().__init__()
        self.setStyleSheet("background-color: black; color: white;")
        self.current_action = None

        self.main_layout = QVBoxLayout(self)

        # Inputs area
        self.label = QLabel("")
        self.label.setStyleSheet("color: white;")
        self.input1 = QLineEdit()
        self.input2 = QLineEdit()
        self.input2.hide()

        self.start_btn = QPushButton("Start")
        self.start_btn.setStyleSheet(BTN_STYLE_GREEN)
        self.start_btn.clicked.connect(self.start_action)

        self.inputs_box = QVBoxLayout()
        self.inputs_box.addWidget(self.label)
        self.inputs_box.addWidget(self.input1)
        self.inputs_box.addWidget(self.input2)
        self.inputs_box.addWidget(self.start_btn)

        self.main_layout.addLayout(self.inputs_box)

        # Results table
        self.table = QTableWidget(0, 3)
        self.table.setStyleSheet("""
            QTableWidget {
                color: white;
                background-color: #222;
                gridline-color: #444;
            }
            QHeaderView::section {
                background-color: #C0392B;
                color: white;
                font-weight: bold;
                padding: 4px;
                border: 1px solid #444;
            }
        """)
        self.table.setHorizontalHeaderLabels(["IP / Host", "MAC / Port Status", "Vendor / Notes"])
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.main_layout.addWidget(self.table)

        # Back
        self.back_btn = QPushButton("Back")
        self.back_btn.setStyleSheet(BTN_STYLE_RED)
        self.back_btn.clicked.connect(self.back.emit)
        self.main_layout.addWidget(self.back_btn, alignment=Qt.AlignmentFlag.AlignLeft)

        self.thread: QThread | None = None
        self.worker: Worker | None = None

    def set_action(self, action: str):
        self.current_action = action
        self.input1.clear()
        self.input2.clear()
        self.input2.hide()

        mapping = {
                "network": "Enter the network (e.g.: 192.168.1.0/24)",
                "os": "Enter IP to detect OS / MAC",
                "top": "Enter IP to scan top ports",
                "range": "Enter IP and range (e.g.: 20-100)",
                "all": "Enter IP to scan all ports",
                "host": "Enter IP to check if reachable",
        }
        self.label.setText(mapping.get(action, ""))

        if action == "range":
            self.input2.setPlaceholderText("مثال: 20-100")
            self.input2.show()

        self.table.setRowCount(0)

    def start_action(self):
        if not self.current_action:
            return

        ip_or_net = self.input1.text().strip()
        extra = self.input2.text().strip() if self.input2.isVisible() else ""

        if self.current_action in {"network", "os", "top", "all", "host"} and not ip_or_net:
            QMessageBox.warning(self, "Warning", "Please enter IP/Network.")
            return

        if self.current_action == "range":
            if not ip_or_net or "-" not in extra:
                QMessageBox.warning(self, "Warning", "Please enter a range like 20-100.")
                return

        # Fix QThread deletion error
        try:
            if self.thread is not None and self.thread.isRunning():
                QMessageBox.information(self, "Info", "A scan is currently running.")
                return
        except RuntimeError:
            # Thread object deleted, ignore and continue
            self.thread = None

        self.start_btn.setEnabled(False)
        self.thread = QThread()
        self.worker = Worker(self.current_action, ip_or_net, extra)
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.finished.connect(self.on_results)
        self.worker.error.connect(self.on_error)
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)
        self.thread.start()

    def on_results(self, rows: list[tuple]):
        self.start_btn.setEnabled(True)
        self.table.setRowCount(0)
        for r in rows:
            row = self.table.rowCount()
            self.table.insertRow(row)
            for col, val in enumerate(r[:3]):
                item = QTableWidgetItem(str(val))
                item.setForeground(Qt.GlobalColor.white)
                self.table.setItem(row, col, item)

    def on_error(self, msg: str):
        self.start_btn.setEnabled(True)
        QMessageBox.critical(self, "Error", msg)

# -------- Main Window --------
class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Scanner GUI (PyQt6)")
        self.resize(950, 600)
        self.setStyleSheet("background-color: black; color: white;")

        self.stack = QStackedWidget()
        self.p1 = Page1()
        self.p2 = Page2()
        self.p3 = Page3()

        self.stack.addWidget(self.p1)
        self.stack.addWidget(self.p2)
        self.stack.addWidget(self.p3)

        layout = QVBoxLayout(self)
        layout.addWidget(self.stack)

        self.p1.go_next.connect(lambda: self.stack.setCurrentIndex(1))
        self.p2.choose_action.connect(self.goto_action)
        self.p2.back_btn.clicked.connect(lambda: self.stack.setCurrentIndex(0))
        self.p3.back.connect(lambda: self.stack.setCurrentIndex(1))

    def goto_action(self, action_key: str):
        self.p3.set_action(action_key)
        self.stack.setCurrentIndex(2)

def main():
    app = QApplication(sys.argv)
    w = MainWindow()
    w.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
