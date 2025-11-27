import requests

class ShodanLookup:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://api.shodan.io"

    def lookup_ip(self, ip):
        try:
            url = f"{self.base_url}/shodan/host/{ip}?key={self.api_key}"
            res = requests.get(url)
            if res.status_code == 200:
                data = res.json()
                return {
                    "ip": data.get("ip_str"),
                    "org": data.get("org"),
                    "os": data.get("os"),
                    "ports": data.get("ports"),
                    "hostnames": data.get("hostnames")
                }
            else:
                return {"error": f"Status Code {res.status_code}"}
        except Exception as e:
            return {"error": str(e)}
