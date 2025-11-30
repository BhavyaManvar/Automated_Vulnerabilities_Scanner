from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QLabel, QLineEdit, QTextEdit,
    QPushButton, QVBoxLayout, QHBoxLayout, QMessageBox, QCheckBox
)
from PyQt5.QtCore import Qt
import sys, json
from scanner.xss_scanner import XSSScanner
from scanner.sqli_scanner import SQLiScanner
from scanner.csrf_scanner import CSRFScanner
from scanner.redirect_scanner import RedirectScanner
from scanner.shodan_lookup import ShodanLookup
from scanner.utils import validate_url, save_report


class AutoVulnScannerGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AutoVulnScanner")
        self.setGeometry(100, 100, 900, 700)

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)

        # Header Label
        self.header_label = QLabel("AutoVulnScanner - Summer Internship 1 by Bhavya Manvar")
        self.header_label.setStyleSheet("""
            font-size: 22px;
            font-weight: bold;
            color: #2c3e50;
	    padding: 10px;
            background-color: #ecf0f1;
            margin-bottom: 10px;
            border-bottom: 2px solid #3498db;
        """)
        self.header_label.setAlignment(Qt.AlignCenter)

        self.url_label = QLabel("Target URL:")
        self.url_entry = QLineEdit()
        self.url_entry.setPlaceholderText("https://example.com")

        self.shodan_check = QCheckBox("Run Shodan Recon")

        self.scan_button = QPushButton("Start Scan")
        self.scan_button.setStyleSheet("""
            QPushButton {
                background-color: #007acc;
                color: white;
                font-weight: bold;
                padding: 6px;
                border-radius: 6px;
            }
            QPushButton:hover {
                background-color: #005999;
            }
        """)
        self.scan_button.clicked.connect(self.start_scan)

        self.output_box = QTextEdit()
        self.output_box.setReadOnly(True)
        self.output_box.setStyleSheet("""
            background-color: #1e1e1e;
            color: #d4d4d4;
            font-family: Consolas, monospace;
            font-size: 13px;
        """)

        layout = QVBoxLayout()
        layout.addWidget(self.header_label)
        layout.addWidget(self.url_label)
        layout.addWidget(self.url_entry)
        layout.addWidget(self.shodan_check)
        layout.addWidget(self.scan_button)
        layout.addWidget(self.output_box)

        self.central_widget.setLayout(layout)

    def log(self, message):
        self.output_box.append(f"<pre>{message}</pre>")
        QApplication.processEvents()

    def highlight_payloads(self, text):
        import re
        payload_color = "#ffb86c"  # Eye-friendly orange for payloads
        pattern = r'(\"[^\"]*\"|\'.*?\'|<[^>]+>)'

        def replacer(match):
            payload = match.group(0)
            return f'<span style="color:{payload_color}; font-weight:bold;">{payload}</span>'

        highlighted = re.sub(pattern, replacer, text)
        return highlighted

    def start_scan(self):
        target_url = self.url_entry.text().strip()

        if not validate_url(target_url):
            QMessageBox.critical(self, "Invalid URL", "Please enter a valid URL.")
            return

        report = {"target": target_url, "vulnerabilities": {}}
        self.output_box.clear()

        if self.shodan_check.isChecked():
            self.log("[*] Fetching Shodan Info...")
            api_key = "L3FY5HbTxhdC2ziAPrpSrZfbWCAGVGgI"
            ip = target_url.replace("http://", "").replace("https://", "").split("/")[0]
            shodan_info = ShodanLookup(api_key).lookup_ip(ip)
            report["shodan"] = shodan_info
            self.log("[*] Shodan Data:<br>" + self.highlight_payloads(json.dumps(shodan_info, indent=4)))

        # XSS Scan
        self.log("[*] Starting XSS Scan...")
        form_results = XSSScanner(target_url).scan()
        self.log("[+] XSS Results:<br>" + self.highlight_payloads(json.dumps(form_results, indent=4)))
        report['vulnerabilities']['xss'] = form_results

        # SQLi Scan
        self.log("[*] Starting SQLi Scan...")
        sqli_results = SQLiScanner(target_url).scan()
        self.log("[+] SQLi Results:<br>" + self.highlight_payloads(json.dumps(sqli_results, indent=4)))
        report['vulnerabilities']['sqli'] = sqli_results

        # Open Redirect Scan
        self.log("[*] Starting Open Redirect Scan...")
        redirect_results = RedirectScanner(target_url).scan()
        self.log("[+] Open Redirect Results:<br>" + self.highlight_payloads(json.dumps(redirect_results, indent=4)))
        report['vulnerabilities']['open_redirect'] = redirect_results

        # CSRF Scan
        self.log("[*] Starting CSRF Scan...")
        csrf_results = CSRFScanner(target_url).scan()
        self.log("[+] CSRF Results:<br>" + self.highlight_payloads(json.dumps(csrf_results, indent=4)))
        report['vulnerabilities']['csrf'] = csrf_results

        save_report(report)
        self.log("<br><b style='color:#00ff00;'>[✓] Scan complete. Report saved in 'reports/results.json'</b>")
        QMessageBox.information(self, "Scan Complete", "Vulnerability scan completed successfully!")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = AutoVulnScannerGUI()
    window.show()
    sys.exit(app.exec_())
