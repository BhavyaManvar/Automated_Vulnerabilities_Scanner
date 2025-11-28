import requests
import threading
from scanner.form_scanner import FormScanner
from urllib.parse import urlparse, parse_qs, urlencode
import re
from bs4 import BeautifulSoup

class XSSScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.payloads = self.load_payloads("payloads/XSS_script.txt")
        self.results = []

    def load_payloads(self, file_path):
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                return [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"[-] Error loading payloads: {str(e)}")
            return []

    def is_reflected_dangerously(self, html, payload):
        if payload not in html:
            return None

        soup = BeautifulSoup(html, "html.parser")

        for script in soup.find_all("script"):
            if payload in script.text:
                if re.search(r'[^\'"\w]' + re.escape(payload) + r'[^\'"\w]', script.text):
                    return "script_tag"

        if re.search(r'on\w+\s*=\s*["\'].*?' + re.escape(payload) + r'.*?["\']', html, re.IGNORECASE):
            return "event_attr"

        if re.search(r'>\s*' + re.escape(payload) + r'\s*<', html):
            return "html_body"

        return "reflected"

    def request(self, url, method='get', data=None, timeout=5):
        try:
            if method == 'get':
                res = requests.get(url, timeout=timeout)
            elif method == 'post':
                res = requests.post(url, data=data, timeout=timeout)
            else:
                raise ValueError("Unsupported HTTP method")
            return res
        except Exception as e:
            print(f"[-] Request error: {str(e)}")
            return None

    def scan_payload(self, payload):
        parsed = urlparse(self.target_url)
        query_params = parse_qs(parsed.query)

        # URL scanning (no query params)
        if not query_params:
            test_url = f"{self.target_url}?q={payload}"
            res = self.request(test_url)
            if res:
                context = self.is_reflected_dangerously(res.text, payload)
                if context:
                    print(f"[+] XSS Found (no param)! Payload: {payload} | Context: {context}")
                    self.results.append({
                        "type": "url",
                        "payload": payload,
                        "url": test_url,
                        "context": context,
                        "parameter": "q"
                    })
        else:
            # URL scanning with params
            for param in query_params:
                temp_params = query_params.copy()
                temp_params[param] = payload
                new_query = urlencode(temp_params, doseq=True)
                test_url = parsed._replace(query=new_query).geturl()
                res = self.request(test_url)
                if res:
                    context = self.is_reflected_dangerously(res.text, payload)
                    if context:
                        print(f"[+] XSS Found in param '{param}'! Payload: {payload} | Context: {context}")
                        self.results.append({
                            "type": "url",
                            "payload": payload,
                            "url": test_url,
                            "context": context,
                            "parameter": param
                        })

        # Form scanning
        form_results = FormScanner(self.target_url, payload).scan_forms()
        for fr in form_results:
            print(f"[+] XSS Found in Form! Payload: {payload} | Context: {fr['context']}")
            self.results.append({
                "type": "form",
                "payload": payload,
                "context": fr.get("context"),
                "action": fr.get("action"),
                "method": fr.get("method"),
                "inputs": fr.get("inputs")
            })

    def scan(self):
        threads = []
        for payload in self.payloads:
            t = threading.Thread(target=self.scan_payload, args=(payload,))
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

        print("\n[✓] Scan Complete.")
        return self.results
