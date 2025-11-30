import json
import os
import validators
import requests
from bs4 import BeautifulSoup

def extract_forms(url):
    try:
        res = requests.get(url, timeout=5)
        soup = BeautifulSoup(res.content, "html.parser")
        return soup.find_all("form")
    except Exception as e:
        print(f"[-] Failed to fetch forms: {e}")
        return []


def validate_url(url):
    # Basic URL validation
    return url.startswith("http://") or url.startswith("https://")

def save_report(report):
    try:
        with open("reports/results.json", "w") as f:
            json.dump(report, f, indent=4)
    except Exception as e:
        print(f"Error saving report: {str(e)}")

