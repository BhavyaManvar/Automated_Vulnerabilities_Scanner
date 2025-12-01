# AutoVulnScanner

**Automated vulnerability scanner** — a Python-based, extensible scanner that unifies XSS, SQLi, CSRF, and Open Redirect detection with optional Shodan lookups and a modern PyQt GUI. Designed as a professional, career-ready project that you can extend, plug into CI, or use as the foundation for a bug-bounty automation toolkit.

---

## Table of Contents

1. [Project overview](#project-overview)
2. [Key features](#key-features)
3. [Repository layout](#repository-layout)
4. [Requirements](#requirements)
5. [Installation](#installation)
6. [Configuration](#configuration)
7. [Usage](#usage)

   * [CLI mode](#cli-mode)
   * [GUI mode (PyQt)](#gui-mode-pyqt)
8. [Payloads & how to add new tests](#payloads--how-to-add-new-tests)
9. [Scanner modules & architecture](#scanner-modules--architecture)
10. [Output / results format](#output--results-format)
11. [Extending the scanner / integrating ML](#extending-the-scanner--integrating-ml)
12. [Testing & troubleshooting](#testing--troubleshooting)
13. [Roadmap](#roadmap)
14. [Contributing](#contributing)
15. [License & credits](#license--credits)

---

## Project overview

AutoVulnScanner is built to automate common web application vulnerability checks while remaining modular and auditable. The scanner is intentionally Python-first (no wrappers around black-box SaaS) so you can inspect requests, payloads, and detection logic. It supports both a command-line interface for scripting and a PyQt GUI for interactive scans.

The project focuses on: XSS, SQLi, CSRF, and Open Redirect detection, plus optional reconnaissance via Shodan. Results are saved under a `results/` folder for later analysis.

---

## Key features

* Parameter-based and form-based testing for XSS and SQLi.
* CSRF token discovery and basic CSRF exploitation checks.
* Open redirect detection (including parameter fuzzing using `redirection_params` and `redirection_script`).
* Optional Shodan integration for target enrichment (requires user Shodan API key).
* Modular scanner core — add new scanners by dropping modules into `scanner/`.
* Payload-driven testing: payloads live in `payloads/` as plain text files for easy editing.
* Results saved in `results/` with human-readable JSON and optional CSV export.
* PyQt GUI to configure, run, and view scan results interactively.

---

## Repository layout

```
AutoVulnScanner/
├─ main.py                      # CLI / entrypoint (example)
├─ gui.py                       # PyQt GUI entrypoint
├─ requirements.txt             # pip dependencies
├─ README.md
├─ payloads/
│  ├─ xss_script                # XSS payloads
│  ├─ sqli_script               # SQLi payloads
│  ├─ csrf_script (optional)    # CSRF probe payloads
│  ├─ redirection_script        # redirection payload templates
│  └─ redirection_params        # common redirect param names
├─ scanner/
│  ├─ __init__.py
│  ├─ xss_scanner.py
│  ├─ sqli_scanner.py
│  ├─ csrf_scanner.py
│  ├─ redirect_scanner.py
│  ├─ form_scanner.py           # form parsing + auto-fill helpers
│  ├─ shodan_lookup.py
│  └─ utils.py                  # shared helpers (requests wrapper, logging, output)
├─ results/                     # scan outputs (auto-created)
└─ docs/                        # optional design docs & examples
```

> Note: The payload filenames above are the project defaults. Your scanner uses these exact names (`xss_script`, `sqli_script`, `redirection_script`, `redirection_params`) so keep them in `payloads/`.

---

## Requirements

* Python 3.10+ (3.11 recommended)
* pip

Python packages (install via `pip install -r requirements.txt`):

* requests
* beautifulsoup4
* PyQt5 (or PyQt6, adjust `gui.py` accordingly)
* lxml (optional, faster HTML parsing)
* python-dotenv (optional, for API keys/config)
* scikit-learn / tensorflow (optional — if you enable ML-based risk classification)

If you plan to use Shodan features, also sign up for a Shodan API key and export it to your environment or add it to `.env`.

---

## Installation

1. Clone the repository:

```bash
git clone https://your-repo-url/AutoVulnScanner.git
cd AutoVulnScanner
```

2. Create a virtual environment and install dependencies:

```bash
python -m venv venv
source venv/bin/activate    # on Windows: venv\Scripts\activate
pip install -r requirements.txt
```

3. Create the `results/` and `payloads/` folders if they don't exist (the app will create them automatically on first run, but you can prepopulate payloads):

```bash
mkdir results
mkdir payloads
# copy sample payload files from docs/samples or create your own
```

4. (Optional) Add a `.env` file with keys:

```
SHODAN_API_KEY=xxxxxxxxxxxxxxxx
```

---

## Configuration

Configuration is intentionally minimal. Most scanner options are passed via CLI flags or GUI controls. For reusable automation you can edit `config.yaml` or export environment variables used by `main.py`.

Important configuration options you may want to set:

* `CONCURRENCY` — number of worker threads for concurrent requests
* `TIMEOUT` — request timeout in seconds
* `USER_AGENT` — default User-Agent header used for scans
* `FOLLOW_REDIRECTS` — whether the scanner should follow 3xx redirects
* `SHODAN_API_KEY` — Shodan API key if using the `shodan_lookup` module

---

## Usage

### CLI mode

Run a scan from the command line. `main.py` is a lightweight entrypoint that demonstrates scanning a single URL.

```bash
# basic scan (default checks)
python main.py --target https://example.com

# run specific checks only
python main.py --target https://example.com --checks xss,sqli

# increase verbosity and concurrent workers
python main.py --target https://example.com --checks xss --workers 10 --verbose
```

CLI flags (examples):

* `--target` (required) — URL to scan
* `--checks` — comma-separated list from {xss,sqli,csrf,redirect}
* `--out` — output path (default `results/<target>-<timestamp>.json`)
* `--workers` — number of concurrent worker threads
* `--follow-redirects` — boolean

### GUI mode (PyQt)

Run the GUI to configure scans interactively:

```bash
python gui.py
```

GUI features:

* Add one or more targets
* Select which checks to run
* Configure concurrency, timeout and custom headers
* View live progress and open saved scan reports

---

## Payloads & how to add new tests

Payloads are plain text files in the `payloads/` directory. Each file contains one payload per line. The scanner reads these files at runtime and uses them for inj
