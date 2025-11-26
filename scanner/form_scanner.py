import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import re

class FormScanner:
    def __init__(self, url, payload):
        self.url = url
        self.payload = payload
        self.session = requests.Session()

    def get_all_forms(self):
        try:
            res = self.session.get(self.url, timeout=10)
            soup = BeautifulSoup(res.text, "html.parser")
            return soup.find_all("form")
        except Exception as e:
            print(f"[-] Error fetching forms: {e}")
            return []

    def get_form_details(self, form):
        details = {
            "action": form.get("action"),
            "method": form.get("method", "get").lower(),
            "inputs": []
        }
        for input_tag in form.find_all(["input", "textarea"]):
            input_type = input_tag.get("type", "text")
            input_name = input_tag.get("name")
            if input_name:
                details["inputs"].append({
                    "type": input_type,
                    "name": input_name
                })
        return details

    def submit_form(self, form_details):
        target_url = urljoin(self.url, form_details["action"])
        data = {}
        for input_field in form_details["inputs"]:
            if input_field["type"] in ["text", "search", "hidden", "textarea"]:
                data[input_field["name"]] = self.payload
            else:
                data[input_field["name"]] = "test"

        try:
            if form_details["method"] == "post":
                res = self.session.post(target_url, data=data, timeout=30)
            else:
                res = self.session.get(target_url, params=data, timeout=30)
            return res.text, target_url
        except Exception as e:
            print(f"[-] Error submitting form: {e}")
            return "", target_url

    def is_reflected_dangerously(self, html):
        matches = []

        # Inside <script> tags with heuristic check
        for script in BeautifulSoup(html, "html.parser").find_all("script"):
            if self.payload in script.text:
                if re.search(r'[^\'"\w]' + re.escape(self.payload) + r'[^\'"\w]', script.text):
                    matches.append("script_tag")

        # Inline event handlers
        if re.search(r'on\w+\s*=\s*["\'].*?' + re.escape(self.payload) + r'.*?["\']', html, re.IGNORECASE):
            matches.append("event_attr")

        # Unquoted HTML body reflection
        if re.search(r'>\s*' + re.escape(self.payload) + r'\s*<', html):
            matches.append("html_body")

        return matches

    def scan_forms(self):
        vulnerable_forms = []
        forms = self.get_all_forms()
        for form in forms:
            details = self.get_form_details(form)
            response_text, submitted_url = self.submit_form(details)
            contexts = self.is_reflected_dangerously(response_text)
            if contexts:
                vulnerable_forms.append({
                    "url": submitted_url,
                    "payload": self.payload,
                    "method": details["method"],
                    "inputs": details["inputs"],
                    "context": contexts
                })
        return vulnerable_forms