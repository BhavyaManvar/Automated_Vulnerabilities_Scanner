import requests
import os
from urllib.parse import urlparse

class RedirectScanner:
    def __init__(self, url):
        self.base_url = url.rstrip('/')
        self.payloads = self.load_list_from_file("payloads/Redirection_script.txt")
        self.redirect_params = self.load_list_from_file("payloads/Redirection_params.txt")
        self.endpoints = [""]  # Common redirect endpoints

    def load_list_from_file(self, file_path):
        try:
            with open(file_path, "r") as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"[!] File not found: {file_path}")
            return []
        except Exception as e:
            print(f"[!] Error reading {file_path}: {e}")
            return []

    def is_open_redirect(self, location, payload):
        parsed = urlparse(location)
        return payload in location and parsed.netloc != ""  # External redirect

    def scan(self):
        results = []
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        }

        for endpoint in self.endpoints:
            for param in self.redirect_params:
                for payload in self.payloads:
                    try:
                        full_url = f"{self.base_url}{endpoint}?{param}={payload}"
                        res = requests.get(full_url, headers=headers, allow_redirects=False, timeout=7)
                        location = res.headers.get("Location", "")
                        print(f"[*] Tested: {full_url} | Status: {res.status_code} | Location: {location}")

                        if res.status_code in [300, 301, 302, 303, 307, 308]:
                            if self.is_open_redirect(location, payload):
                                print(f"[+] Open Redirect Found! Endpoint: {endpoint}, Param: {param}, Payload: {payload}")
                                results.append({
                                    "url": full_url,
                                    "param": param,
                                    "payload": payload,
                                    "location": location,
                                    "status_code": res.status_code
                                })
                    except requests.RequestException as e:
                        print(f"[-] Error checking {param}={payload} -> {e}")
        return results
