from bs4 import BeautifulSoup
import requests

class CSRFScanner:
    def __init__(self, url):
        self.url = url

    def scan(self):
        try:
            res = requests.get(self.url, timeout=5)
            soup = BeautifulSoup(res.text, "html.parser")
            forms = soup.find_all("form")
            for form in forms:
                inputs = form.find_all("input")
                has_token = any("csrf" in i.attrs.get("name", "").lower() for i in inputs)
                if not has_token:
                    print(f"[+] CSRF Risk: Form missing CSRF token")
                    return [{"form_action": form.attrs.get("action", "unknown")}]
        except:
            pass
        return []
