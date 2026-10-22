# threat_analyzer.py
# ============================================================
#  THREATVISION PRO - Enterprise SOC Threat Intelligence Portal
# ============================================================
# Run (any ONE of these works - missing packages and server_logs.txt are created automatically):
#   1.  python -m streamlit run threat_analyzer.py
#   2.  python threat_analyzer.py            (the file starts Streamlit by itself)
#   3.  double-click run_app.bat             (Windows)
#
# Pages (sidebar):
#   1. SOC Overview                 (metrics, gauge, donut, status codes, timeline)
#   2. Live Scanner & Simulator     (multi-layer scoring + attack presets)
#   3. Threat Intel & Geo Map       (top malicious IPs, simulated origin map)
#   4. MITRE ATT&CK Mapping         (tactics / techniques detected)
#   5. Reports & Audit              (history, JSON / CSV export, audit log)
#
# Multi-layer scoring engine (total capped at 100):
#   Layer 1  Pattern Matching   (malware, phish, sql injection, ...)   max 80
#   Layer 2  Anomaly Detection  (brute force + scan behaviour)         max 50
#   Layer 3  IP Reputation      (open threat feeds, or a simulated feed) max 70
#
# URL forensics: detects look-alike and obfuscated URLs (inst@gram.com, facebook%.com, gooogle.com,
# xn-- homographs) and an OSINT panel (DNS, WHOIS/RDAP, certificate logs) for any target.
#
# Real-world mode: open threat feeds (IPsum, Feodo, Blocklist.de, Phishing.Database, URLhaus,
# OpenPhish), real log files, real geolocation and optional VirusTotal / AbuseIPDB lookups.
#
# Extra features: sound alerts (beeps + voice, with mute) and a Live Feed page that
# streams simulated log events into server_logs.txt using st.fragment auto-refresh.
#
# NOTE: No input() and no while-loops. Streamlit re-runs this file on
# every click, so buttons + st.session_state replace menu loops.

import base64
import hashlib
import hmac
import html
import inspect
import json
import os
import random
import re
import shutil
import socket
import time
import unicodedata
import webbrowser
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta
from difflib import SequenceMatcher

import importlib
import importlib.util
import subprocess
import sys

# ---------------------------------------------------------------
# 0. AUTO SETUP (so the app runs without manual steps)
# ---------------------------------------------------------------
REQUIRED_PACKAGES = {"streamlit": "streamlit", "plotly": "plotly", "pandas": "pandas"}


def ensure_packages():
    """Install any missing package automatically with pip."""
    missing = []
    for module_name in REQUIRED_PACKAGES:
        if importlib.util.find_spec(module_name) is None:
            missing.append(REQUIRED_PACKAGES[module_name])
    if len(missing) > 0:
        print("ThreatVision: installing missing packages: " + ", ".join(missing))
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install"] + missing)
        except subprocess.CalledProcessError:
            print("Could not install automatically. Run:  python -m pip install " + " ".join(missing))
            sys.exit(1)
        importlib.invalidate_caches()


ensure_packages()

# Always work inside the folder that contains this file, so server_logs.txt,
# threat_report.txt and security_audit.log are found wherever you start the app from.
os.chdir(os.path.dirname(os.path.abspath(__file__)))

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
import streamlit.components.v1 as components


def running_inside_streamlit():
    """True when Streamlit is running this file (False when started with plain python)."""
    try:
        from streamlit.runtime.scriptrunner import get_script_run_ctx
        try:
            return get_script_run_ctx(suppress_warning=True) is not None
        except TypeError:
            return get_script_run_ctx() is not None
    except Exception:
        return False


def find_app_browser():
    """Find Edge or Chrome, so the dashboard can open in its own app window (no tabs, no address bar)."""
    candidates = []
    for variable in ["ProgramFiles(x86)", "ProgramFiles", "LOCALAPPDATA"]:
        base = os.environ.get(variable)
        if base:
            candidates.append(os.path.join(base, "Microsoft", "Edge", "Application", "msedge.exe"))
            candidates.append(os.path.join(base, "Google", "Chrome", "Application", "chrome.exe"))
    for name in ["msedge", "microsoft-edge", "google-chrome", "chrome", "chromium"]:
        found = shutil.which(name)
        if found:
            candidates.append(found)
    for path in candidates:
        if os.path.exists(path):
            return path
    return None


def find_free_port(start=8501):
    """First free TCP port from 8501 upwards."""
    for port in range(start, start + 20):
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            probe.bind(("127.0.0.1", port))
            probe.close()
            return port
        except OSError:
            probe.close()
    return start


def launch_desktop_app():
    """Start the Streamlit server and open the dashboard as an app window."""
    port = find_free_port()
    url = "http://localhost:" + str(port)
    print("Starting ThreatVision Pro on " + url + " ... (press Ctrl+C to stop)")
    server = subprocess.Popen([sys.executable, "-m", "streamlit", "run", os.path.abspath(__file__),
                               "--server.headless", "true", "--server.port", str(port),
                               "--browser.gatherUsageStats", "false"])
    for i in range(60):                                      # wait until the server answers
        try:
            urllib.request.urlopen(url + "/_stcore/health", timeout=1)
            break
        except Exception:
            time.sleep(1)
    browser = find_app_browser()
    if browser:
        subprocess.Popen([browser, "--app=" + url, "--window-size=1440,900"])
    else:
        webbrowser.open(url)
    try:
        server.wait()
    except KeyboardInterrupt:
        server.terminate()


# If someone runs "python threat_analyzer.py": print a password hash, or open the dashboard as an app.
if __name__ == "__main__" and not running_inside_streamlit():
    if "--hash" in sys.argv and len(sys.argv) > sys.argv.index("--hash") + 1:
        new_salt = os.urandom(16).hex()
        print('AUTH_SALT = "' + new_salt + '"')
        print('AUTH_HASH = "' + hashlib.pbkdf2_hmac("sha256", sys.argv[sys.argv.index("--hash") + 1].encode("utf-8"),
                                                 bytes.fromhex(new_salt), 200000).hex() + '"')
        sys.exit(0)
    launch_desktop_app()
    sys.exit(0)


# ---------------------------------------------------------------
# 1. CONSTANTS AND CONFIGURATION
# ---------------------------------------------------------------
LOG_FILE = "server_logs.txt"
REPORT_FILE = "threat_report.txt"
AUDIT_FILE = "security_audit.log"

# Threat levels (highest first) with neon colours
LEVEL_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
LEVEL_COLORS = {"CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#eab308", "LOW": "#22c55e"}
LEVEL_LABELS = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW / SAFE"}
LEVEL_EMOJI = {"CRITICAL": "🔴 CRITICAL", "HIGH": "🟠 HIGH", "MEDIUM": "🟡 MEDIUM", "LOW": "🟢 LOW / SAFE"}

# Sidebar severity filter: label -> minimum score
SEVERITY_FILTERS = {
    "All severities": 0,
    "Medium and above (40+)": 40,
    "High and above (70+)": 70,
    "Critical only (85+)": 85,
}

# Scoring settings (easy to explain and change)
PATTERN_CAP = 80       # Layer 1 maximum
ANOMALY_CAP = 50       # Layer 2 maximum
REPUTATION_CAP = 70
URL_CAP = 80           # Layer 4 (URL forensics) maximum    # Layer 3 maximum
BRUTE_POINTS = 3       # points per failed login (401 / 403)
BRUTE_MIN = 5          # failed logins needed to call it "Brute Force"
SCAN_POINTS = 4        # points per distinct missing page / probed port
SCAN_MIN = 5           # probes needed to call it "Scan / Enumeration"

# Attack types: patterns, base points, MITRE ATT&CK mapping, mitigations.
# "Brute Force" and "Scan / Enumeration" have no patterns because they are
# detected by behaviour (Layer 2), not by keywords.
ATTACK_TYPES = {
    "SQL Injection": {
        "patterns": ["sql_injection", "' or ", "or 1=1", "union select", "drop table"],
        "points": 70,
        "tactic": "Initial Access", "tech_id": "T1190", "technique": "Exploit Public-Facing Application",
        "mitigations": [
            "Use parameterized queries / prepared statements",
            "Deploy a WAF rule that blocks SQL meta-characters",
            "Give the database account least privilege only",
            "Hide detailed SQL error messages from users",
        ],
    },
    "Exploit Attempt": {
        "patterns": ["exploit", "../", "/etc/passwd"],
        "points": 65,
        "tactic": "Initial Access", "tech_id": "T1190", "technique": "Exploit Public-Facing Application",
        "mitigations": [
            "Patch the web server and application frameworks",
            "Block path traversal sequences (../) at the WAF",
            "Run the web service as a low-privilege user",
        ],
    },
    "Malware Delivery": {
        "patterns": ["malware", ".exe", ".sh", ".apk"],
        "points": 60,
        "tactic": "Execution", "tech_id": "T1204", "technique": "User Execution",
        "mitigations": [
            "Block executable downloads (.exe, .sh, .apk) from untrusted hosts",
            "Scan downloads with an endpoint antivirus / sandbox",
            "Add the domain to the proxy / DNS blocklist",
        ],
    },
    "Phishing": {
        "patterns": ["phish", "verify"],
        "points": 55,
        "tactic": "Initial Access", "tech_id": "T1566", "technique": "Phishing",
        "mitigations": [
            "Block the domain at the DNS / email gateway",
            "Warn users and run phishing-awareness training",
            "Enable multi-factor authentication on all accounts",
        ],
    },
    "Credential Probing": {
        "patterns": ["login", "admin"],
        "points": 25,
        "tactic": "Credential Access", "tech_id": "T1110", "technique": "Brute Force",
        "mitigations": [
            "Restrict /admin and /login to trusted IP ranges",
            "Enable multi-factor authentication",
            "Add CAPTCHA and account lockout on login pages",
        ],
    },
    "Brute Force": {
        "patterns": [],
        "points": 0,
        "tactic": "Credential Access", "tech_id": "T1110", "technique": "Brute Force",
        "mitigations": [
            "Rate-limit and temporarily ban IPs with repeated 401/403 responses",
            "Enforce strong passwords and account lockout",
            "Install fail2ban for automatic blocking",
        ],
    },
    "Scan / Enumeration": {
        "patterns": [],
        "points": 0,
        "tactic": "Reconnaissance", "tech_id": "T1595", "technique": "Active Scanning",
        "mitigations": [
            "Block the scanning IP at the firewall",
            "Close unused ports and hide server banners",
            "Alert when one IP requests many missing pages (404)",
        ],
    },
    "Botnet C2": {
        "patterns": [],
        "points": 0,
        "tactic": "Command and Control", "tech_id": "T1071", "technique": "Application Layer Protocol",
        "mitigations": [
            "Block all traffic to and from the C2 address",
            "Check the machines that talked to it for infection",
            "Add the address to the firewall and proxy blocklists",
        ],
    },
    "Lookalike Domain": {
        "patterns": [],
        "points": 0,
        "tactic": "Initial Access", "tech_id": "T1566.002", "technique": "Phishing: Spearphishing Link",
        "mitigations": [
            "Do not click the link and never type a password on it",
            "Open the real website by typing its official address yourself",
            "Block the look-alike domain in the DNS filter and web proxy",
            "Report it to the brand and to Google Safe Browsing",
        ],
    },
}

# Order used to draw the MITRE kill-chain strip
TACTIC_ORDER = ["Reconnaissance", "Initial Access", "Execution", "Credential Access", "Command and Control"]

# Simulated threat feed (AbuseIPDB / VirusTotal style). Keys are IPs or domains.
THREAT_FEED = {
    "203.0.113.45": {"abuse": 95, "vt": 14, "country": "Russia", "lat": 61.5, "lon": 105.3, "category": "Brute Force Botnet"},
    "198.51.100.23": {"abuse": 88, "vt": 9, "country": "China", "lat": 35.9, "lon": 104.2, "category": "Malware Distribution"},
    "198.51.100.88": {"abuse": 40, "vt": 2, "country": "Brazil", "lat": -14.2, "lon": -51.9, "category": "Port Scanner"},
    "faceback.malware.com": {"abuse": 92, "vt": 18, "country": "Netherlands", "lat": 52.1, "lon": 5.3, "category": "Malware Host"},
    "phishing-site.com": {"abuse": 90, "vt": 16, "country": "United States", "lat": 37.1, "lon": -95.7, "category": "Phishing Host"},
}

# Countries used to simulate the origin of unknown public IPs
SIM_COUNTRIES = [
    ("United States", 37.1, -95.7), ("Germany", 51.2, 10.4), ("India", 20.6, 78.9),
    ("Brazil", -14.2, -51.9), ("China", 35.9, 104.2), ("Russia", 61.5, 105.3),
    ("Nigeria", 9.1, 8.7), ("Vietnam", 14.1, 108.3),
]

# ---- Real-world intelligence settings ----
INTEL_MODES = ["Demo (simulated feed)", "Real-world (open feeds)"]
INTEL_MODE = "demo"       # set again on every run in the main section
INTEL_DATA = {}           # parsed open feeds (real mode)
GEO_CACHE = {}            # real IP locations looked up with ip-api.com
INTEL_DIR = "intel_cache"
GEO_FILE = os.path.join(INTEL_DIR, "geo_cache.json")
LOG_BACKUP = "server_logs_backup.txt"
FEED_MAX_AGE_HOURS = 24
FEED_CONFIRM_BONUS = 30   # extra points when a feed CONFIRMS an attack (phishing, malware, botnet C2)
REAL_LOG_LIMIT = 50000    # analyse at most this many log lines
REAL_SAMPLE_LOG_URL = "https://raw.githubusercontent.com/elastic/examples/master/Common%20Data%20Formats/nginx_logs/nginx_logs"

# Open threat feeds (free, no API key). "kind" tells the parser how to read the file.
FEEDS = [
    {"id": "ipsum", "short": "IPsum", "kind": "ipsum", "type_label": "Attacker IPs (30+ lists combined)",
     "name": "IPsum", "url": "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"},
    {"id": "feodo", "short": "Feodo Tracker", "kind": "iplist", "type_label": "Botnet C2 IPs",
     "name": "Feodo Tracker (abuse.ch)", "url": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/feodo.ipset",
     "points": 40, "attack": "Botnet C2", "category": "Botnet C2 server (Feodo Tracker)"},
    {"id": "blocklist_de", "short": "Blocklist.de", "kind": "iplist", "type_label": "Reported attacker IPs",
     "name": "Blocklist.de", "url": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/blocklist_de.ipset",
     "points": 20, "attack": None, "category": "Reported attacker (Blocklist.de)"},
    {"id": "phishdb", "short": "Phishing.Database", "kind": "domains", "type_label": "Phishing domains",
     "name": "Phishing.Database", "url": "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt",
     "points": 40, "attack": "Phishing", "category": "Phishing domain (Phishing.Database)"},
    {"id": "urlhaus", "short": "URLhaus", "kind": "urls", "type_label": "Malware URLs",
     "name": "URLhaus (abuse.ch)", "url": "https://urlhaus.abuse.ch/downloads/text_online/",
     "points": 40, "attack": "Malware Delivery", "category": "Malware URL (URLhaus)"},
    {"id": "openphish", "short": "OpenPhish", "kind": "urls", "type_label": "Phishing URLs",
     "name": "OpenPhish community feed", "url": "https://openphish.com/feed.txt",
     "points": 40, "attack": "Phishing", "category": "Phishing URL (OpenPhish)"},
]

# One-click attack simulator presets
PRESETS = {
    "SQL Injection Payload": {"target": "http://shop.example.com/products.php?id=1' OR 1=1 --", "auth_fails": 0, "ports": 0},
    "Phishing URL": {"target": "http://secure-verify-login.phish-bank.com/login", "auth_fails": 0, "ports": 0},
    "Brute Force Attack": {"target": "203.0.113.45", "auth_fails": 20, "ports": 0},
    "Port Scan Attempt": {"target": "198.51.100.88", "auth_fails": 0, "ports": 25},
    "Safe Domain": {"target": "www.google.com", "auth_fails": 0, "ports": 0},
}

PAGE_ICONS = {
    "Overview": ":material/dashboard:", "Live Scanner": ":material/radar:", "Live Feed": ":material/sensors:",
    "Threat Intel & Map": ":material/public:", "MITRE ATT&CK": ":material/hub:", "Reports & Audit": ":material/description:",
}

PAGES = [
    "Overview",
    "Live Scanner",
    "Live Feed",
    "Threat Intel & Map",
    "MITRE ATT&CK",
    "Reports & Audit",
]

# ---------------------------------------------------------------
# 2. THEMES (Purple Neon, Dark Glass, Neon Green) + CUSTOM CSS
# ---------------------------------------------------------------
THEMES = {
    # 1) Purple neon: deep purple, cyan and pink glow (like the purple reference)
    "Purple Neon": {
        "accent": "#22e4d8", "accent2": "#ff4fa3", "accent3": "#8b5cf6",
        "app_bg": "radial-gradient(1100px 620px at 18% -8%, #2b1060 0%, #140832 42%, #070312 100%)",
        "bg": "#140832", "side": "linear-gradient(180deg, #100a2b 0%, #09041a 100%)", "panel": "#1a0e3d",
        "card_bg": "linear-gradient(160deg, #1f1146 0%, #140a2d 100%)", "card_border": "rgba(139,92,246,0.40)",
        "card_shadow": "0 0 22px rgba(124,58,237,0.22)", "border": "rgba(139,92,246,0.32)",
        "text": "#ece7ff", "muted": "#a094cf", "track": "rgba(255,255,255,0.10)",
        "side_text": "#ece7ff", "side_muted": "#9f93cf", "side_item": "rgba(139,92,246,0.14)",
        "side_border": "rgba(139,92,246,0.35)", "side_input": "#1a0e3d", "side_input_text": "#ece7ff",
        "side_active": "linear-gradient(90deg, rgba(34,228,216,0.24), rgba(255,79,163,0.08))",
        "side_active_border": "#22e4d8", "toggle_on": "#22e4d8", "code_bg": "#0b0618",
    },
    # 2) Dark glass: matte black cards with a soft lavender glow (like the Sophos reference)
    "Dark Glass": {
        "accent": "#8b7bff", "accent2": "#c4b5fd", "accent3": "#60a5fa",
        "app_bg": "radial-gradient(900px 520px at 72% -12%, #2a2a34 0%, #0d0d12 48%, #050507 100%)",
        "bg": "#0d0d12", "side": "linear-gradient(180deg, #0c0c10 0%, #070709 100%)", "panel": "#16161c",
        "card_bg": "linear-gradient(160deg, rgba(255,255,255,0.085) 0%, rgba(255,255,255,0.025) 100%)",
        "card_border": "rgba(255,255,255,0.11)", "card_shadow": "0 10px 28px rgba(0,0,0,0.55)",
        "border": "rgba(255,255,255,0.12)", "text": "#ededf2", "muted": "#8d8d9c", "track": "rgba(255,255,255,0.10)",
        "side_text": "#ededf2", "side_muted": "#85859a", "side_item": "rgba(255,255,255,0.05)",
        "side_border": "rgba(255,255,255,0.11)", "side_input": "#16161c", "side_input_text": "#ededf2",
        "side_active": "linear-gradient(90deg, rgba(255,255,255,0.20), rgba(255,255,255,0.02))",
        "side_active_border": "#ffffff", "toggle_on": "#8b7bff", "code_bg": "#08080b",
    },
    # 3) Neon green: black-green canvas with bright green glow (like the green reference)
    "Neon Green": {
        "accent": "#2ee86b", "accent2": "#a3e635", "accent3": "#22d3ee",
        "app_bg": "radial-gradient(1000px 560px at 16% -10%, #0f3d25 0%, #07180f 44%, #030a06 100%)",
        "bg": "#07180f", "side": "linear-gradient(180deg, #0a2015 0%, #06130c 100%)", "panel": "#0c2016",
        "card_bg": "linear-gradient(160deg, #0f2c1b 0%, #0a1d12 100%)", "card_border": "rgba(46,232,107,0.32)",
        "card_shadow": "0 0 18px rgba(46,232,107,0.14)", "border": "rgba(46,232,107,0.28)",
        "text": "#e6fff0", "muted": "#7fb596", "track": "rgba(46,232,107,0.14)",
        "side_text": "#e6fff0", "side_muted": "#78ad90", "side_item": "rgba(46,232,107,0.10)",
        "side_border": "rgba(46,232,107,0.28)", "side_input": "#0c2016", "side_input_text": "#e6fff0",
        "side_active": "linear-gradient(90deg, rgba(46,232,107,0.28), rgba(46,232,107,0.04))",
        "side_active_border": "#2ee86b", "toggle_on": "#2ee86b", "code_bg": "#04100a",
    },
}
DEFAULT_THEME = "Purple Neon"

# Colours used by the Plotly charts and HTML components (filled by apply_theme)
MODE = "dark"
ACCENT = ""
ACCENT2 = ""
ACCENT3 = ""
BG = ""
PANEL = ""
BORDER = ""
TEXT = ""
MUTED = ""
TRACK = ""
GRID = "rgba(255,255,255,0.07)"
PALETTE = []


def apply_theme(theme_name):
    """Copy the chosen theme colours into global variables used by charts and components."""
    global ACCENT, ACCENT2, ACCENT3, BG, PANEL, BORDER, TEXT, MUTED, TRACK, PALETTE
    theme = THEMES[theme_name]
    ACCENT = theme["accent"]
    ACCENT2 = theme["accent2"]
    ACCENT3 = theme["accent3"]
    BG = theme["bg"]
    PANEL = theme["panel"]
    BORDER = theme["border"]
    TEXT = theme["text"]
    MUTED = theme["muted"]
    TRACK = theme["track"]
    PALETTE = [ACCENT, ACCENT2, ACCENT3, "#f59e0b", "#ef4444"]


apply_theme(DEFAULT_THEME)

# Streamlit's own widgets read some colours from .streamlit/config.toml (default theme).
CONFIG_TEXT = """[theme]
base = "dark"
primaryColor = "#22e4d8"
backgroundColor = "#140832"
secondaryBackgroundColor = "#1d1042"
textColor = "#ece7ff"
font = "sans serif"
"""

# Config files that older versions of this app created. They are replaced automatically.
OLD_CONFIG_TEXTS = [
    """[theme]
base = "dark"
primaryColor = "#4f6bff"
backgroundColor = "#0b1220"
secondaryBackgroundColor = "#111a2e"
textColor = "#e6ebf5"
font = "sans serif"
""",
    """[theme]
base = "light"
primaryColor = "#2563eb"
backgroundColor = "#f4f7fb"
secondaryBackgroundColor = "#ffffff"
textColor = "#0f172a"
font = "sans serif"
""",
    """[theme]
base = "light"
primaryColor = "#1d4ed8"
backgroundColor = "#e8f0fe"
secondaryBackgroundColor = "#ffffff"
textColor = "#0b1b3a"
font = "sans serif"
""",
]


def ensure_streamlit_config():
    """Create .streamlit/config.toml ("w" mode) if it is missing or is one of the old versions."""
    path = os.path.join(".streamlit", "config.toml")
    try:
        if os.path.exists(path):
            file = open(path, "r")
            existing = file.read().strip()
            file.close()
            known = False
            for old in OLD_CONFIG_TEXTS:
                if existing == old.strip():
                    known = True
            if not known:
                return                  # the analyst changed it: leave it alone
        os.makedirs(".streamlit", exist_ok=True)
        file = open(path, "w")
        file.write(CONFIG_TEXT)
        file.close()
    except OSError:
        pass                            # not critical - the dashboard still works


# Tokens like __A__ and __CARD_BG__ are replaced by build_css() with the colours of the chosen theme.
CSS_TEMPLATE = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
html, body, [class*="css"], .stApp { font-family: 'Inter', 'Segoe UI', Roboto, Arial, sans-serif; }
.stApp { background: __APP_BG__; background-attachment: fixed; color: __TEXT__; color-scheme: dark; }
[data-testid="stHeader"] { background: transparent; }
[data-testid="stHeader"] * { color: __TEXT__; }
[data-testid="stAppDeployButton"], [data-testid="stDecoration"], footer { display: none; }
a { color: __A__; }
h1, h2, h3, h4, h5 { color: __TEXT__ !important; font-weight: 600; letter-spacing: 0; }
h4 { font-size: 1.05rem; margin-top: 1.1rem; }
[data-testid="stMarkdownContainer"], [data-testid="stMarkdownContainer"] p, [data-testid="stMarkdownContainer"] li { color: __TEXT__; }
[data-testid="stMarkdownContainer"] code { background: __TRACK__; color: __TEXT__; padding: 1px 6px; border-radius: 4px; }
[data-testid="stCaptionContainer"], [data-testid="stCaptionContainer"] * { color: __MUTED__ !important; }
[data-testid="stWidgetLabel"], [data-testid="stWidgetLabel"] * { color: __TEXT__ !important; }
[data-testid="stSpinner"] * { color: __TEXT__ !important; }
hr { border: none; border-top: 1px solid __BORDER__; }
::-webkit-scrollbar { width: 9px; height: 9px; }
::-webkit-scrollbar-thumb { background: __CARD_BORDER__; border-radius: 6px; }
::-webkit-scrollbar-track { background: transparent; }
[data-testid="stSidebar"], [data-testid="stSidebar"] > div:first-child, [data-testid="stSidebarContent"] { background: __SIDE__ !important; }
[data-testid="stSidebar"] { border-right: 1px solid __SIDE_BORDER__; }
[data-testid="stSidebar"] [data-testid="stMarkdownContainer"], [data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p, [data-testid="stSidebar"] [data-testid="stWidgetLabel"] * { color: __SIDE_TEXT__ !important; }
[data-testid="stSidebar"] [data-testid="stCaptionContainer"] * { color: __SIDE_MUTED__ !important; }
[data-testid="stSidebar"] [data-testid="stSidebarCollapseButton"] *, [data-testid="stSidebar"] button[kind="headerNoPadding"] * { color: __SIDE_TEXT__ !important; }
.brand { display: flex; align-items: center; gap: 10px; padding: 2px 2px 4px 2px; }
.brand-logo { width: 34px; height: 34px; border-radius: 9px; background: linear-gradient(135deg, __A__, __B__); color: #05030c; display: flex; align-items: center; justify-content: center; font-weight: 800; font-size: 0.95rem; }
.brand-name { font-weight: 700; font-size: 1.05rem; color: __SIDE_TEXT__; line-height: 1.1; letter-spacing: 0.02em; }
.brand-sub { font-size: 0.7rem; color: __SIDE_MUTED__; margin-top: 1px; }
.profile { text-align: center; padding: 14px 6px 4px 6px; }
.avatar-ring { position: relative; width: 98px; height: 98px; margin: 0 auto 10px auto; padding: 3px; border-radius: 50%; background: conic-gradient(from 200deg, __A__, __B__, __C__, __A__); box-shadow: 0 0 22px __A__55; }
.avatar { border-radius: 50%; object-fit: cover; display: flex; align-items: center; justify-content: center; background: linear-gradient(135deg, __A__, __B__); color: #05030c; font-weight: 800; }
.avatar-ring .avatar { width: 100%; height: 100%; border: 3px solid __BG__; box-sizing: border-box; font-size: 1.9rem; }
.online { position: absolute; right: 6px; bottom: 8px; width: 14px; height: 14px; border-radius: 50%; background: #22c55e; border: 2px solid __BG__; }
.p-name { font-weight: 700; font-size: 1.05rem; color: __SIDE_TEXT__; }
.p-role { margin-top: 2px; font-size: 0.78rem; color: __SIDE_MUTED__; }
.risk-box { margin-top: 14px; margin-bottom: 12px; padding: 12px 14px; border: 1px solid __SIDE_BORDER__; border-radius: 12px; background: __SIDE_ITEM__; }
.risk-row { display: flex; justify-content: space-between; align-items: center; font-size: 0.72rem; color: __SIDE_MUTED__; text-transform: uppercase; letter-spacing: 0.1em; }
.risk-row b { font-size: 0.8rem; letter-spacing: 0.06em; }
.risk-bar { height: 6px; margin-top: 10px; border-radius: 3px; background: __SIDE_BORDER__; overflow: hidden; }
.risk-fill { height: 100%; border-radius: 3px; }
.risk-foot { margin-top: 8px; font-size: 0.76rem; color: __SIDE_MUTED__; }
.side-label { margin: 20px 0 6px 2px; font-size: 0.7rem; font-weight: 600; letter-spacing: 0.14em; text-transform: uppercase; color: __SIDE_MUTED__; }
[class*="st-key-navoff_"] [data-testid="stButton"], [class*="st-key-navon_"] [data-testid="stButton"] { width: 100%; }
[class*="st-key-navoff_"] button, [class*="st-key-navon_"] button { width: 100%; justify-content: flex-start !important; text-align: left; padding: 9px 12px; margin-bottom: 2px; border: 1px solid transparent !important; border-left: 3px solid transparent !important; border-radius: 8px !important; background: transparent !important; box-shadow: none !important; }
[class*="st-key-navoff_"] button p, [class*="st-key-navon_"] button p { color: __SIDE_TEXT__ !important; text-align: left; font-weight: 500; font-size: 0.95rem; }
[class*="st-key-navoff_"] button [data-testid="stIconMaterial"] { color: __SIDE_MUTED__ !important; }
[class*="st-key-navon_"] button [data-testid="stIconMaterial"] { color: __SIDE_ACTIVE_BORDER__ !important; }
[class*="st-key-navoff_"] button:hover { background: __SIDE_ITEM__ !important; }
[class*="st-key-navon_"] button { background: __SIDE_ACTIVE__ !important; border-left: 3px solid __SIDE_ACTIVE_BORDER__ !important; }
[class*="st-key-navon_"] button p { font-weight: 700; }
[data-testid="stSidebar"] .stButton > button, [data-testid="stSidebar"] .stDownloadButton > button { background: __SIDE_ITEM__; color: __SIDE_TEXT__; border: 1px solid __SIDE_BORDER__; border-radius: 8px; }
[data-testid="stSidebar"] .stButton > button p { color: __SIDE_TEXT__; }
[data-testid="stSidebar"] .stButton > button:hover { border-color: __A__; }
[data-testid="stSidebar"] [data-baseweb="select"] > div, [data-testid="stSidebar"] [data-testid="stSelectbox"] [role="group"] { background: __SIDE_INPUT__ !important; border: 1px solid __SIDE_BORDER__ !important; }
[data-testid="stSidebar"] [data-testid="stSelectbox"] input { color: __SIDE_INPUT_TEXT__ !important; -webkit-text-fill-color: __SIDE_INPUT_TEXT__ !important; }
[data-testid="stSidebar"] [data-testid="stSelectbox"] svg, [data-testid="stSidebar"] [data-testid="stSelectbox"] button { color: __SIDE_INPUT_TEXT__ !important; fill: __SIDE_INPUT_TEXT__ !important; }
[data-testid="stSidebar"] .stTextInput input { background: __SIDE_INPUT__; color: __SIDE_INPUT_TEXT__; border: 1px solid __SIDE_BORDER__; }
[data-testid="stSidebar"] [data-testid="stFileUploaderDropzone"] { background: __SIDE_ITEM__; border: 1px dashed __SIDE_BORDER__; }
[data-testid="stSidebar"] [data-testid="stFileUploaderDropzone"] small, [data-testid="stSidebar"] [data-testid="stFileUploaderDropzone"] span, [data-testid="stSidebar"] [data-testid="stFileUploaderDropzone"] div { color: __SIDE_TEXT__ !important; }
[data-testid="stSidebar"] [data-testid="stFileUploaderDropzone"] button { background: __SIDE_ITEM__ !important; color: __SIDE_TEXT__ !important; border: 1px solid __SIDE_BORDER__ !important; }
[data-testid="stSidebar"] [data-testid="stFileUploaderDropzone"] button * { color: __SIDE_TEXT__ !important; }
[data-testid="stSidebar"] [data-testid="stExpander"] { background: __SIDE_ITEM__; border: 1px solid __SIDE_BORDER__; }
[data-testid="stSidebar"] [data-testid="stExpander"] summary, [data-testid="stSidebar"] [data-testid="stExpander"] summary * { color: __SIDE_TEXT__ !important; }
[data-testid="stSidebar"] [data-testid="stToggle"], [data-testid="stSidebar"] [data-testid="stCheckbox"] { padding: 8px 12px; border: 1px solid __SIDE_BORDER__; border-radius: 8px; background: __SIDE_ITEM__; }
[data-testid="stSidebar"] [data-testid="stAlert"] { background: __SIDE_ITEM__ !important; border: 1px solid __SIDE_BORDER__; border-left: 4px solid __SIDE_ACTIVE_BORDER__; }
[data-testid="stSidebar"] [data-testid="stAlert"] * { color: __SIDE_TEXT__ !important; }
.side-stat { margin-top: 14px; padding: 10px 14px; border: 1px solid __SIDE_BORDER__; border-radius: 12px; background: __SIDE_ITEM__; font-size: 0.82rem; }
.side-stat div { display: flex; justify-content: space-between; padding: 5px 0; border-bottom: 1px solid __SIDE_BORDER__; color: __SIDE_MUTED__; }
.side-stat div:last-child { border-bottom: none; }
.side-stat b { color: __SIDE_TEXT__; font-weight: 600; }
.side-foot { margin-top: 14px; text-align: center; font-size: 0.72rem; color: __SIDE_MUTED__; }
.topbar { display: flex; justify-content: space-between; align-items: center; gap: 16px; flex-wrap: wrap; margin: 4px 0 18px 0; }
.crumb { font-size: 0.72rem; font-weight: 600; letter-spacing: 0.16em; text-transform: uppercase; color: __MUTED__; }
.crumb span { color: __A__; }
.page-title { margin-top: 3px; font-size: 1.8rem; font-weight: 700; color: __TEXT__; line-height: 1.2; }
.top-right { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.chip { display: inline-flex; align-items: center; gap: 6px; padding: 6px 13px; border-radius: 999px; border: 1px solid __BORDER__; background: __CARD_BG__; font-size: 0.8rem; color: __MUTED__; }
.chip b { color: __TEXT__; font-weight: 600; }
.user-chip { display: inline-flex; align-items: center; gap: 9px; padding: 4px 15px 4px 4px; border-radius: 999px; border: 1px solid __CARD_BORDER__; background: __CARD_BG__; font-size: 0.85rem; font-weight: 600; color: __TEXT__; }
.user-chip .avatar { width: 32px; height: 32px; font-size: 0.8rem; }
.live-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; background: #22c55e; box-shadow: 0 0 8px #22c55e; }
.kpi-strip { display: flex; gap: 10px; flex-wrap: wrap; margin: 0 0 18px 0; }
.card, [class*="st-key-chartcard_"] { background: __CARD_BG__; border: 1px solid __CARD_BORDER__; border-radius: 14px; box-shadow: __CARD_SHADOW__; }
[class*="st-key-chartcard_"] { padding: 14px 16px 6px 16px; margin-bottom: 14px; }
.card { padding: 16px 18px; margin-bottom: 14px; }
.card-title { margin-bottom: 6px; font-size: 0.76rem; font-weight: 600; letter-spacing: 0.12em; text-transform: uppercase; color: __A__; }
.kpi { text-align: center; padding: 18px 10px 14px 10px; }
.ring-wrap { position: relative; width: 108px; height: 108px; margin: 0 auto 10px auto; }
.ring { position: absolute; top: 0; right: 0; bottom: 0; left: 0; border-radius: 50%; -webkit-mask: radial-gradient(circle, transparent 57%, #000 58%), repeating-conic-gradient(#000 0deg 9deg, transparent 9deg 12deg); -webkit-mask-composite: source-in; mask: radial-gradient(circle, transparent 57%, #000 58%), repeating-conic-gradient(#000 0deg 9deg, transparent 9deg 12deg); mask-composite: intersect; }
.ring-num { position: absolute; top: 0; right: 0; bottom: 0; left: 0; display: flex; align-items: center; justify-content: center; font-size: 1.5rem; font-weight: 700; color: __TEXT__; }
.kpi-label { font-size: 0.76rem; font-weight: 600; letter-spacing: 0.12em; text-transform: uppercase; color: __A__; }
.kpi-cap { margin-top: 3px; font-size: 0.78rem; color: __MUTED__; }
.seg-row { display: flex; align-items: center; gap: 10px; margin: 11px 0; }
.seg-label { width: 104px; font-size: 0.8rem; color: __MUTED__; white-space: nowrap; }
.seg { display: flex; flex: 1; gap: 3px; }
.seg i { flex: 1; height: 16px; border-radius: 2px; display: block; }
.seg-val { width: 40px; text-align: right; font-size: 0.9rem; font-weight: 700; color: __TEXT__; }
.gbar-row { margin: 13px 0; }
.gbar-head { display: flex; justify-content: space-between; margin-bottom: 6px; font-size: 0.84rem; color: __MUTED__; }
.gbar-head b { color: __TEXT__; }
.gbar-track { height: 8px; border-radius: 4px; background: __TRACK__; overflow: hidden; }
.gbar-fill { height: 100%; border-radius: 4px; }
[data-testid="stMetric"] { background: __CARD_BG__; border: 1px solid __CARD_BORDER__; border-radius: 12px; padding: 14px 16px; box-shadow: __CARD_SHADOW__; }
[data-testid="stMetricValue"], [data-testid="stMetricValue"] * { color: __TEXT__ !important; font-weight: 600; }
[data-testid="stMetricDelta"], [data-testid="stMetricDelta"] * { color: __MUTED__ !important; }
[data-testid="stMetricValue"] > div { white-space: normal !important; overflow: visible !important; text-overflow: clip !important; word-break: break-word; }
[data-testid="stMetricLabel"], [data-testid="stMetricLabel"] * { color: __MUTED__ !important; text-transform: uppercase; letter-spacing: 0.08em; font-size: 0.76rem; }
.stButton > button, .stDownloadButton > button, [data-testid="stFormSubmitButton"] > button { background: __PANEL__; color: __TEXT__; border: 1px solid __BORDER__; border-radius: 8px; font-weight: 500; transition: border-color 0.15s, background 0.15s; }
.stButton > button p, .stDownloadButton > button p { color: inherit; }
.stButton > button:hover, .stDownloadButton > button:hover { border-color: __A__; color: __A__; }
.stButton > button[kind="primary"], [data-testid="stFormSubmitButton"] > button[kind="primaryFormSubmit"] { background: linear-gradient(90deg, __A__, __B__); border: none; color: #05030c; font-weight: 700; }
.stButton > button[kind="primary"] p, [data-testid="stFormSubmitButton"] > button p { color: #05030c; }
.stButton > button[kind="primary"]:hover { filter: brightness(1.1); color: #05030c; }
.stTextInput input { background: __PANEL__; color: __TEXT__; border: 1px solid __BORDER__; border-radius: 8px; }
.stTextInput input:focus { border-color: __A__; box-shadow: 0 0 0 1px __A__; }
[data-baseweb="select"] > div, [data-testid="stSelectbox"] [role="group"] { background: __PANEL__ !important; border: 1px solid __BORDER__ !important; border-radius: 8px !important; }
[data-baseweb="select"] * { color: __TEXT__ !important; }
[data-testid="stSelectbox"] input { color: __TEXT__ !important; -webkit-text-fill-color: __TEXT__ !important; }
[data-testid="stSelectbox"] svg, [data-testid="stSelectbox"] button { color: __MUTED__ !important; fill: __MUTED__ !important; }
label:has(input[role="switch"]:checked) > span + div { background: __A__ !important; }
label:has(input[role="switch"]:not(:checked)) > span + div { background: __TRACK__ !important; }
[data-testid="stSidebar"] label:has(input[role="switch"]:checked) > span + div { background: __TOGGLE_ON__ !important; }
[data-testid="stSidebar"] label:has(input[role="switch"]:not(:checked)) > span + div { background: __SIDE_BORDER__ !important; }
[data-baseweb="popover"] ul, [data-baseweb="popover"] [data-baseweb="menu"] { background: __PANEL__ !important; border: 1px solid __BORDER__; }
[data-baseweb="popover"] li { background: transparent !important; color: __TEXT__ !important; }
[data-baseweb="popover"] li:hover, [data-baseweb="popover"] li[aria-selected="true"] { background: __TRACK__ !important; }
[data-testid="stSelectboxVirtualDropdown"] { background: __PANEL__ !important; border: 1px solid __BORDER__; border-radius: 8px; }
[data-testid="stSelectboxVirtualDropdown"] [role="option"], [data-testid="stSelectboxVirtualDropdown"] [role="option"] * { color: __TEXT__ !important; }
[data-testid="stSelectboxVirtualDropdown"] [role="option"]:hover, [data-testid="stSelectboxVirtualDropdown"] [role="option"][aria-selected="true"] { background: __TRACK__ !important; }
[data-testid="stSlider"] [data-testid="stTickBarMin"], [data-testid="stSlider"] [data-testid="stTickBarMax"], [data-testid="stSlider"] [data-testid="stSliderThumbValue"] { color: __TEXT__ !important; }
[data-testid="stExpander"] { border: 1px solid __CARD_BORDER__; border-radius: 12px; background: __CARD_BG__; }
[data-testid="stExpander"] summary, [data-testid="stExpander"] details > summary, [data-testid="stExpander"] details[open] > summary { background: transparent !important; }
[data-testid="stExpander"] summary, [data-testid="stExpander"] summary * { color: __TEXT__ !important; }
[data-testid="stExpander"] details { background: transparent; }
[data-testid="stAlert"] { background: __PANEL__ !important; border: 1px solid __BORDER__; border-left: 4px solid __A__; border-radius: 10px; }
[data-testid="stAlert"] * { color: __TEXT__ !important; }
[data-testid="stForm"] { background: transparent; border: none; padding: 0; }
.tbl-wrap { overflow: auto; max-height: 460px; margin: 6px 0 14px 0; border: 1px solid __CARD_BORDER__; border-radius: 12px; background: __CARD_BG__; box-shadow: __CARD_SHADOW__; }
table.tbl { width: 100%; border-collapse: collapse; font-size: 0.88rem; }
table.tbl th { position: sticky; top: 0; padding: 10px 12px; text-align: left; white-space: nowrap; font-size: 0.72rem; font-weight: 600; letter-spacing: 0.08em; text-transform: uppercase; color: __A__; background: __PANEL__; border-bottom: 1px solid __BORDER__; }
table.tbl td { padding: 9px 12px; color: __TEXT__; border-bottom: 1px solid __BORDER__; vertical-align: top; }
table.tbl tr:last-child td { border-bottom: none; }
table.tbl tr:hover td { background: __TRACK__; }
.bar { display: flex; align-items: center; gap: 8px; min-width: 110px; }
.bar-track { flex: 1; height: 6px; border-radius: 3px; background: __TRACK__; overflow: hidden; }
.bar-fill { height: 100%; border-radius: 3px; }
.codebox { display: block; margin: 6px 0 12px 0; padding: 12px 14px; max-height: 360px; overflow: auto; white-space: pre; border-radius: 10px; border: 1px solid __BORDER__; background: __CODE_BG__; color: #e2e8f0; font-family: Consolas, 'Courier New', monospace; font-size: 0.85rem; }
.badge { display: inline-block; padding: 2px 10px; border-radius: 6px; font-weight: 600; font-size: 0.78rem; letter-spacing: 0.04em; }
.badge.critical { color: #f87171; background: #ef444428; }
.badge.high { color: #fb923c; background: #f9731628; }
.badge.medium { color: #facc15; background: #eab30828; }
.badge.low { color: #4ade80; background: #22c55e28; }
.risk-card { display: flex; align-items: center; gap: 24px; padding: 18px 22px; margin: 8px 0 14px 0; border: 1px solid __CARD_BORDER__; border-left: 5px solid; border-radius: 12px; background: __CARD_BG__; box-shadow: __CARD_SHADOW__; }
.risk-card.critical { border-left-color: #ef4444; }
.risk-card.high { border-left-color: #f97316; }
.risk-card.medium { border-left-color: #eab308; }
.risk-card.low { border-left-color: #22c55e; }
.risk-score { font-size: 2.9rem; font-weight: 700; line-height: 1; }
.risk-max { margin-left: 3px; font-size: 1rem; font-weight: 500; color: __MUTED__; }
.risk-note { margin-left: 12px; font-size: 0.88rem; color: __MUTED__; }
.risk-target { margin-top: 8px; font-family: Consolas, 'Courier New', monospace; font-size: 0.9rem; color: __MUTED__; word-break: break-all; }
.alert-item { padding: 10px 12px; margin-bottom: 8px; border: 1px solid __BORDER__; border-left: 3px solid; border-radius: 8px; background: __TRACK__; font-size: 0.88rem; color: __MUTED__; }
.alert-item.critical { border-left-color: #ef4444; }
.alert-item.high { border-left-color: #f97316; }
.alert-item.medium { border-left-color: #eab308; }
.alert-item .ip { font-family: Consolas, 'Courier New', monospace; font-weight: 600; color: __TEXT__; }
.alert-item .sc { float: right; font-weight: 700; }
.kc-row { display: flex; gap: 10px; flex-wrap: wrap; margin: 6px 0 14px 0; }
.kc-box { flex: 1; min-width: 150px; padding: 12px; text-align: center; border: 1px solid __CARD_BORDER__; border-radius: 12px; background: __CARD_BG__; color: __MUTED__; font-size: 0.78rem; letter-spacing: 0.08em; box-shadow: __CARD_SHADOW__; }
.kc-box.active { border-color: #ef4444; color: __TEXT__; background: #ef44441f; }
.kc-box .num { display: block; font-size: 1.7rem; font-weight: 700; }
.exec-title { margin-bottom: 8px; font-size: 0.76rem; font-weight: 600; letter-spacing: 0.12em; text-transform: uppercase; color: __A__; }
.exec-card ul { margin: 0; padding-left: 18px; }
.exec-card li { margin: 6px 0; color: __TEXT__; }
.lookalike-box { display: flex; flex-wrap: wrap; align-items: center; gap: 22px; padding: 16px 20px; margin: 8px 0 14px 0; border: 1px solid __CARD_BORDER__; border-left: 5px solid #ef4444; border-radius: 12px; background: __CARD_BG__; box-shadow: __CARD_SHADOW__; }
.lookalike-box.safe { border-left-color: #22c55e; }
.lookalike-box .cap { font-size: 0.72rem; font-weight: 600; letter-spacing: 0.08em; text-transform: uppercase; color: __MUTED__; }
.lookalike-box .dom { margin-top: 3px; font-family: Consolas, 'Courier New', monospace; font-size: 1.05rem; font-weight: 700; word-break: break-all; color: __TEXT__; }
.lookalike-box .fake { color: #f87171; }
.lookalike-box .real { color: #4ade80; }
.lookalike-box .arrow { font-size: 1.6rem; color: __MUTED__; }
.login-logo { width: 58px; height: 58px; margin: 6px auto 12px auto; border-radius: 16px; background: linear-gradient(135deg, __A__, __B__); color: #05030c; display: flex; align-items: center; justify-content: center; font-weight: 800; font-size: 1.3rem; box-shadow: 0 0 26px __A__66; }
.login-title { text-align: center; font-size: 1.65rem; font-weight: 700; color: __TEXT__; }
.login-sub { text-align: center; margin: 2px 0 18px 0; font-size: 0.9rem; color: __MUTED__; }
.login-foot { margin-top: 14px; text-align: center; font-size: 0.74rem; color: __MUTED__; }
</style>
"""

# Extra CSS when "Presentation mode" is switched on (bigger text, no Streamlit menu)
PRESENTATION_CSS = """
<style>
[data-testid="stToolbar"], #MainMenu, footer { display: none !important; }
html { font-size: 19px; }
.block-container { padding-top: 1.2rem; }
</style>
"""


def build_css(theme_name, presentation):
    """Fill the CSS template with the colours of the chosen theme."""
    theme = THEMES[theme_name]
    tokens = {
        "__SIDE_ACTIVE_BORDER__": theme["side_active_border"], "__SIDE_INPUT_TEXT__": theme["side_input_text"],
        "__SIDE_BORDER__": theme["side_border"], "__SIDE_ACTIVE__": theme["side_active"],
        "__SIDE_MUTED__": theme["side_muted"], "__SIDE_INPUT__": theme["side_input"],
        "__SIDE_ITEM__": theme["side_item"], "__SIDE_TEXT__": theme["side_text"], "__SIDE__": theme["side"],
        "__CARD_BORDER__": theme["card_border"], "__CARD_SHADOW__": theme["card_shadow"], "__CARD_BG__": theme["card_bg"],
        "__TOGGLE_ON__": theme["toggle_on"], "__CODE_BG__": theme["code_bg"], "__APP_BG__": theme["app_bg"],
        "__BORDER__": theme["border"], "__PANEL__": theme["panel"], "__MUTED__": theme["muted"],
        "__TEXT__": theme["text"], "__TRACK__": theme["track"], "__BG__": theme["bg"],
        "__A__": theme["accent"], "__B__": theme["accent2"], "__C__": theme["accent3"],
    }
    css = CSS_TEMPLATE
    if presentation:
        css = css + PRESENTATION_CSS
    for key in sorted(tokens, key=len, reverse=True):
        css = css.replace(key, tokens[key])
    return css


# ---- theme-aware replacements for st.dataframe and st.code ----
def render_table(data, hide_index=True, column_config=None):
    """Show a table as themed HTML (the same look in every theme). Drop-in for st.dataframe."""
    df = pd.DataFrame(data)
    bar_columns = []
    if column_config is not None and "Risk Score" in column_config:
        bar_columns = ["Risk Score"]
    head = ""
    for column in df.columns:
        head = head + "<th>" + html.escape(str(column)) + "</th>"
    body = ""
    for row in df.itertuples(index=False):
        body = body + "<tr>"
        for column, value in zip(df.columns, row):
            if value is None or (isinstance(value, float) and value != value):
                text = "-"
            else:
                text = str(value)
            if column in bar_columns and text.replace(".", "").isdigit():
                score = int(float(text))
                color = LEVEL_COLORS[get_level(score)]
                cell = ('<div class="bar"><div class="bar-track"><div class="bar-fill" style="width:' + str(min(score, 100))
                        + '%;background:' + color + ';"></div></div><span>' + str(score) + '</span></div>')
            else:
                cell = html.escape(text)
            body = body + "<td>" + cell + "</td>"
        body = body + "</tr>"
    st.markdown('<div class="tbl-wrap"><table class="tbl"><thead><tr>' + head + '</tr></thead><tbody>' + body
                + '</tbody></table></div>', unsafe_allow_html=True)


def code_block(text, max_chars=20000):
    """Dark code / log box that looks right in every theme. Drop-in for st.code."""
    if len(text) > max_chars:
        text = text[:max_chars] + "\n... (shortened)"
    st.markdown('<div class="codebox">' + html.escape(text) + '</div>', unsafe_allow_html=True)


# ---- small colour helpers and dashboard components (rings, LED bars, gradient bars) ----
def hex_to_rgba(color, alpha):
    """#22e4d8 -> rgba(34,228,216,alpha)"""
    red = int(color[1:3], 16)
    green = int(color[3:5], 16)
    blue = int(color[5:7], 16)
    return "rgba(" + str(red) + "," + str(green) + "," + str(blue) + "," + str(alpha) + ")"


def lerp_color(color_a, color_b, t):
    """Colour between two hex colours (t from 0 to 1)."""
    mixed = []
    for i in (1, 3, 5):
        first = int(color_a[i:i + 2], 16)
        second = int(color_b[i:i + 2], 16)
        mixed.append(round(first + (second - first) * t))
    return "#%02x%02x%02x" % (mixed[0], mixed[1], mixed[2])


def ring_card_html(label, value, percent, caption, colors=None):
    """KPI card with a segmented ring (like the purple reference dashboard)."""
    if colors is None:
        colors = (ACCENT, ACCENT2)
    percent = max(0, min(100, int(percent)))
    ring_style = ("background: conic-gradient(from 0deg, " + colors[0] + " 0%, " + colors[1] + " " + str(percent)
                  + "%, " + TRACK + " " + str(percent) + "%, " + TRACK + " 100%);")
    return ('<div class="card kpi"><div class="ring-wrap"><div class="ring" style="' + ring_style + '"></div>'
            '<div class="ring-num">' + html.escape(str(value)) + '</div></div>'
            '<div class="kpi-label">' + html.escape(label) + '</div>'
            '<div class="kpi-cap">' + html.escape(caption) + '</div></div>')


def segbar_html(label, value, maximum, colors, segments=24):
    """One LED-style segmented bar (like the coloured bars in the purple reference)."""
    filled = 0
    if maximum > 0:
        filled = round(segments * value / maximum)
    if value > 0 and filled == 0:
        filled = 1
    cells = ""
    for i in range(segments):
        if i < filled:
            color = lerp_color(colors[0], colors[1], i / max(segments - 1, 1))
        else:
            color = TRACK
        cells = cells + '<i style="background:' + color + ';"></i>'
    return ('<div class="seg-row"><span class="seg-label">' + html.escape(label) + '</span><div class="seg">'
            + cells + '</div><span class="seg-val">' + str(value) + '</span></div>')


def gbar_html(label, value, maximum):
    """Gradient progress bar with a label and a number."""
    width = 0
    if maximum > 0:
        width = round(100 * value / maximum)
    return ('<div class="gbar-row"><div class="gbar-head"><span>' + html.escape(label) + '</span><b>' + str(value)
            + '</b></div><div class="gbar-track"><div class="gbar-fill" style="width:' + str(width)
            + '%;background:linear-gradient(90deg,' + ACCENT + ',' + ACCENT2 + ');"></div></div></div>')


def card_container(name):
    """A container that the CSS paints as a card (newer Streamlit: via its key, older: plain border)."""
    try:
        return st.container(key="chartcard_" + name)
    except TypeError:
        return st.container(border=True)


def chart_card(title, fig, key):
    """A Plotly chart inside a themed card with a small title."""
    with card_container(key):
        if title != "":
            st.markdown('<div class="card-title">' + html.escape(title) + '</div>', unsafe_allow_html=True)
        show_chart(fig, key)


# ---------------------------------------------------------------
# 3. FILE HANDLING (r / w / a modes)
# ---------------------------------------------------------------
def read_logs():
    """Read server_logs.txt ("r" mode). Returns a list of non-empty lines."""
    lines = []
    try:
        file = open(LOG_FILE, "r", encoding="utf-8", errors="replace")
        for line in file:
            line = line.strip()
            if line != "":
                lines.append(line)
        file.close()
    except FileNotFoundError:
        pass                          # missing file -> empty list
    return lines


def read_text_file(filename):
    """Read any text file ("r" mode). Returns "" when the file does not exist."""
    text = ""
    try:
        file = open(filename, "r")
        text = file.read()
        file.close()
    except FileNotFoundError:
        pass
    return text


def write_report(summary):
    """Overwrite threat_report.txt ("w" mode) with the latest summary."""
    file = open(REPORT_FILE, "w")
    file.write("===== THREATVISION PRO - THREAT REPORT =====\n")
    file.write("Generated: " + str(datetime.now()) + "\n")
    file.write("Total logs processed: " + str(summary["total_logs"]) + "\n")
    file.write("Unique IPs: " + str(len(summary["ips"])) + "\n")
    file.write("Critical: " + str(summary["counts"]["CRITICAL"]) + " | High: " + str(summary["counts"]["HIGH"])
               + " | Medium: " + str(summary["counts"]["MEDIUM"]) + " | Low: " + str(summary["counts"]["LOW"]) + "\n")
    file.write("Risk index: " + str(summary["risk_index"]) + "/100 | Security health: " + str(summary["health"]) + "%\n\n")
    file.write("--- IP THREAT LIST ---\n")
    for ip in summary["ips"]:
        result = summary["ips"][ip]["result"]
        vector_names = []
        for vector in result["vectors"]:
            vector_names.append(vector["Vector"])
        file.write(ip + " | Score: " + str(result["score"]) + " | " + result["level"]
                   + " | Vectors: " + ", ".join(vector_names) + "\n")
    file.close()


def write_audit(message):
    """Add one timestamped line to security_audit.log ("a" = append mode)."""
    file = open(AUDIT_FILE, "a")
    file.write(str(datetime.now()) + " | " + message + "\n")
    file.close()


def create_sample_logs():
    """Create a demo server_logs.txt ("w" mode) so the portal has data to show."""
    # (ip, path, status code, how many times, hour of day)
    # "{n}" in a path becomes 1, 2, 3 ... so every request hits a different page
    sample = [
        ("192.168.1.10", "/index.html", "200", 12, "09"),
        ("192.168.1.11", "/about.html", "200", 8, "10"),
        ("192.168.1.12", "/products", "200", 10, "11"),
        ("192.168.1.13", "/contact", "200", 6, "16"),
        ("198.51.100.9", "/index.html", "200", 5, "12"),
        ("10.0.0.5", "/login", "401", 6, "13"),
        ("10.0.0.5", "/index.html", "200", 2, "13"),
        ("10.0.0.9", "/admin", "403", 2, "17"),
        ("172.16.0.8", "/probe{n}", "404", 12, "14"),
        ("172.16.0.8", "/api/report", "500", 2, "14"),
        ("172.16.0.8", "/index.html", "200", 3, "14"),
        ("203.0.113.45", "/admin", "403", 5, "02"),
        ("203.0.113.45", "/login", "401", 4, "03"),
        ("198.51.100.23", "/download/setup.exe", "200", 2, "15"),
        ("198.51.100.23", "/setup.exe", "404", 3, "15"),
        ("192.0.2.99", "/products?id=1'+OR+1=1--", "500", 3, "04"),
        ("203.0.113.77", "/cgi-bin/exploit.sh", "404", 4, "20"),
        ("203.0.113.77", "/index.html", "200", 1, "20"),
    ]
    file = open(LOG_FILE, "w")
    minute = 0
    for item in sample:
        for i in range(item[3]):
            minute = (minute + 7) % 60
            path = item[1].replace("{n}", str(i + 1))
            line = (item[0] + ' - - [07/Oct/2026:' + item[4] + ':' + str(minute).zfill(2)
                    + ':00 +0000] "GET ' + path + ' HTTP/1.1" ' + item[2] + "\n")
            file.write(line)
    file.close()


def rescan_logs():
    """Callback for the sidebar re-scan button."""
    write_audit("Manual re-scan triggered by analyst")


# ---------------------------------------------------------------
# 4. TEXT / LOG LINE HELPERS
# ---------------------------------------------------------------
def get_ip(line):
    """The first word of a log line is the IP address."""
    parts = line.split()
    if len(parts) > 0:
        return parts[0]
    return ""


def get_status_code(line):
    """The first 3-digit word of a log line is the HTTP status code."""
    for word in line.split():
        if word.isdigit() and len(word) == 3:
            return word
    return ""


def get_hour(line):
    """Hour from a timestamp like [07/Oct/2026:13:05:11 +0000] (or "")."""
    if "[" in line:
        stamp = line.split("[")[1]
        parts = stamp.split(":")
        if len(parts) > 1:
            return parts[1]
    return ""


def get_request_text(line):
    """The request is the text inside the quotes: "GET /login HTTP/1.1"."""
    if '"' in line:
        return line.split('"')[1]
    return line


def get_path(line):
    """URL path of a log line, e.g. /login."""
    parts = get_request_text(line).split()
    if len(parts) >= 2:
        return parts[1]
    return ""


def normalize_text(text):
    """Lower-case and decode simple URL encoding so patterns match."""
    text = text.lower()
    text = text.replace("%20", " ").replace("+", " ").replace("%27", "'")
    return text


def clean_input(text):
    """Trim spaces and remove markdown link symbols like [text](url)."""
    text = text.strip()
    if "](" in text:
        text = text.split("](")[1].replace(")", "")
    return text.lower()


def is_ip(text):
    """True when text looks like an IPv4 address."""
    parts = text.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit() or int(part) > 255:
            return False
    return True


def is_private_ip(ip):
    """True for internal / LAN addresses (10.x, 192.168.x, 172.16-31.x)."""
    parts = ip.split(".")
    if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("127."):
        return True
    if parts[0] == "172" and 16 <= int(parts[1]) <= 31:
        return True
    return False


def get_host(target):
    """Extract the host name / IP from a URL or plain text."""
    host = target
    if target.count(":") > 1 and "//" not in target:
        return target                 # IPv6 address: keep it as it is
    if "//" in host:
        host = host.split("//")[1]
    host = host.split("/")[0].split("?")[0]
    if "@" in host:
        host = host.rsplit("@", 1)[1]        # text before the @ is only a user name
    host = host.split(":")[0]
    return host


# ---------------------------------------------------------------
# 5. THREAT INTELLIGENCE HELPERS
# ---------------------------------------------------------------
def pattern_matches(pattern, text):
    """Check one pattern. File extensions (.exe) must end the word, so
    '.sh' matches 'run.sh' but not '.shop'."""
    if pattern.startswith("."):
        found = re.search(re.escape(pattern) + r"(?![a-z0-9_])", text)
        return found is not None
    return pattern in text


def detect_attack_types(text):
    """Layer 1 helper: return the attack types whose patterns appear in text."""
    text = normalize_text(text)
    found = []
    for name in ATTACK_TYPES:
        for pattern in ATTACK_TYPES[name]["patterns"]:
            if pattern_matches(pattern, text):
                found.append(name)
                break                 # one match is enough for this type
    return found


def feed_lookup(target):
    """Threat-feed lookup. Real mode uses the open feeds, demo mode uses the simulated feed."""
    if INTEL_MODE == "real":
        return real_feed_lookup(target)
    host = get_host(target)
    for key in THREAT_FEED:
        if is_ip(key):
            if key == host:
                return THREAT_FEED[key]
        elif key in host:
            return THREAT_FEED[key]
    return None


def geo_lookup(host):
    """Origin of an IP. Real mode: looked-up locations only. Demo mode: simulated."""
    if INTEL_MODE == "real":
        if host in GEO_CACHE:
            return GEO_CACHE[host]
        if is_ip(host) and is_private_ip(host):
            return {"country": "Internal Network", "lat": None, "lon": None}
        return {"country": "Not looked up", "lat": None, "lon": None}
    feed = feed_lookup(host)
    if feed is not None:
        return {"country": feed["country"], "lat": feed["lat"], "lon": feed["lon"]}
    if is_ip(host):
        if is_private_ip(host):
            return {"country": "Internal Network", "lat": None, "lon": None}
        total = 0
        for part in host.split("."):
            total = total + int(part)
        choice = SIM_COUNTRIES[total % len(SIM_COUNTRIES)]
        return {"country": choice[0], "lat": choice[1], "lon": choice[2]}
    return {"country": "Unknown", "lat": None, "lon": None}


def get_level(score):
    """Score -> CRITICAL / HIGH / MEDIUM / LOW."""
    if score >= 85:
        return "CRITICAL"
    elif score >= 70:
        return "HIGH"
    elif score >= 40:
        return "MEDIUM"
    else:
        return "LOW"


def make_vector(name, layer, points):
    """One matched attack vector (a row of the vectors table)."""
    info = ATTACK_TYPES[name]
    return {
        "Vector": name,
        "Layer": layer,
        "Points": points,
        "MITRE Tactic": info["tactic"],
        "Technique": info["tech_id"] + " " + info["technique"],
    }


def score_entity(types, auth_fails, scan_count, feed, url_points=0):
    """THE SCORING ENGINE - combines the three layers into one score.
    types      : attack types found by pattern matching
    auth_fails : number of failed logins (401/403)
    scan_count : number of different missing pages / ports probed
    feed       : threat-feed entry (or None)
    url_points : points from the URL forensics check (scanner only)"""
    vectors = []

    # Layer 1: pattern matching
    pattern_points = 0
    for name in types:
        pattern_points = pattern_points + ATTACK_TYPES[name]["points"]
        vectors.append(make_vector(name, "Pattern Matching", ATTACK_TYPES[name]["points"]))
    if pattern_points > PATTERN_CAP:
        pattern_points = PATTERN_CAP

    # Layer 2: anomaly detection (brute force + scanning behaviour)
    brute_points = auth_fails * BRUTE_POINTS
    scan_points = scan_count * SCAN_POINTS
    if auth_fails >= BRUTE_MIN:
        vectors.append(make_vector("Brute Force", "Anomaly Detection", brute_points))
    if scan_count >= SCAN_MIN:
        vectors.append(make_vector("Scan / Enumeration", "Anomaly Detection", scan_points))
    anomaly_points = brute_points + scan_points
    if anomaly_points > ANOMALY_CAP:
        anomaly_points = ANOMALY_CAP

    # Layer 3: IP reputation from the simulated threat feed
    reputation_points = 0
    if feed is not None:
        if "points" in feed:                       # real feed: points were already calculated
            reputation_points = feed["points"]
        else:                                      # simulated feed
            reputation_points = feed["abuse"] * 3 // 10 + min(feed["vt"], 10)
        if feed.get("attack_type") is not None:    # a feed confirmed an attack type
            vectors.append(make_vector(feed["attack_type"], "Threat Intel", reputation_points))
    if reputation_points > REPUTATION_CAP:
        reputation_points = REPUTATION_CAP

    # Layer 4: URL forensics (look-alike and obfuscation tricks)
    if url_points > URL_CAP:
        url_points = URL_CAP
    if url_points > 0:
        vectors.append(make_vector("Lookalike Domain", "URL Forensics", url_points))

    total = pattern_points + anomaly_points + reputation_points + url_points
    if total > 100:
        total = 100

    return {
        "score": total,
        "level": get_level(total),
        "layers": {
            "Pattern Matching": pattern_points,
            "Anomaly Detection": anomaly_points,
            "IP Reputation": reputation_points,
            "URL Forensics": url_points,
        },
        "vectors": vectors,
        "feed": feed,
    }


def analyze_target(target, logs, sim_auth_fails=0, sim_ports=0):
    """Scan one URL / IP typed (or simulated) in the Live Scanner."""
    types = detect_attack_types(target)

    # Look for this target inside server_logs.txt
    auth_fails = 0
    missing_paths = []
    for line in logs:
        if target in line.lower():
            code = get_status_code(line)
            if code == "401" or code == "403":
                auth_fails = auth_fails + 1
            elif code == "404":
                path = get_path(line)
                if path not in missing_paths:
                    missing_paths.append(path)

    auth_fails = auth_fails + sim_auth_fails         # simulated brute force
    scan_count = len(missing_paths) + sim_ports      # simulated port scan

    forensics = analyze_url_forensics(target)
    result = score_entity(types, auth_fails, scan_count, feed_lookup(target), forensics["points"])
    result["forensics"] = forensics
    result["target"] = target
    result["host"] = get_host(target)
    result["auth_fails"] = auth_fails
    result["scan_count"] = scan_count
    result["sim_auth"] = sim_auth_fails
    result["sim_ports"] = sim_ports
    return result


def build_firewall_rules(result):
    """Recommended firewall rules as a list of (title, command)."""
    rules = []
    host = result["host"]
    names = []
    for vector in result["vectors"]:
        names.append(vector["Vector"])

    # Only build commands for safe-looking hosts (letters, digits, dots, dashes)
    safe_host = re.fullmatch(r"[a-z0-9.\-]+", host) is not None

    if is_ip(host) and result["level"] != "LOW":
        rules.append(("Block the attacker IP", "sudo iptables -A INPUT -s " + host + " -j DROP"))
        rules.append(("Log the IP for forensics", 'sudo iptables -I INPUT -s ' + host + ' -j LOG --log-prefix "THREATVISION: "'))
        if "Brute Force" in names:
            rules.append(("Ban with fail2ban", "sudo fail2ban-client set sshd banip " + host))
        if "Scan / Enumeration" in names:
            rules.append(("Drop repeated scan probes",
                          "sudo iptables -A INPUT -m recent --name portscan --rcheck --seconds 600 -s " + host + " -j DROP"))
        if "Botnet C2" in names:
            rules.append(("Block outbound traffic to the C2 server", "sudo iptables -A OUTPUT -d " + host + " -j DROP"))
    elif safe_host and ("Phishing" in names or "Malware Delivery" in names or "Lookalike Domain" in names):
        rules.append(("Sinkhole the malicious domain", "echo '0.0.0.0 " + host + "' | sudo tee -a /etc/hosts"))

    if "SQL Injection" in names:
        rules.append(("WAF rule (ModSecurity)",
                      'SecRule ARGS "@detectSQLi" "id:1001,phase:2,deny,status:403,log,msg:\'SQL Injection blocked\'"'))
    if "Exploit Attempt" in names:
        rules.append(("WAF rule - path traversal",
                      'SecRule REQUEST_URI "@contains ../" "id:1002,phase:1,deny,status:403,log"'))
    return rules


def build_mitigations(result):
    """Unique list of recommended mitigation steps for a scan result."""
    steps = []
    for vector in result["vectors"]:
        for step in ATTACK_TYPES[vector["Vector"]]["mitigations"]:
            if step not in steps:
                steps.append(step)
    if result["feed"] is not None:
        steps.append("Add to blocklist: threat feed confidence is " + str(result["feed"]["abuse"]) + "%")
    if len(steps) == 0:
        steps.append("No action required - continue routine monitoring")
    return steps


# ---------------------------------------------------------------
# 6. LOG ANALYSIS (builds ONE summary dictionary used by every page)
# ---------------------------------------------------------------
def build_summary(logs):
    ip_info = {}          # ip -> counters collected while reading the logs
    status_counts = {}    # "200" -> number of requests
    hourly_all = {}       # "13" -> requests in that hour
    hourly_threat = {}    # "13" -> threat events in that hour

    for line in logs:
        ip = get_ip(line)
        code = get_status_code(line)
        hour = get_hour(line)
        found = detect_attack_types(get_request_text(line))

        if ip not in ip_info:
            ip_info[ip] = {"requests": 0, "failed": 0, "auth_fails": 0, "missing_paths": [], "types": []}
        info = ip_info[ip]
        info["requests"] = info["requests"] + 1

        if code == "401" or code == "403":
            info["auth_fails"] = info["auth_fails"] + 1
        if code == "404":
            path = get_path(line)
            if path not in info["missing_paths"]:
                info["missing_paths"].append(path)
        if code == "401" or code == "403" or code == "404":
            info["failed"] = info["failed"] + 1
        for name in found:
            if name not in info["types"]:
                info["types"].append(name)

        status_counts[code] = status_counts.get(code, 0) + 1

        if hour != "":
            hourly_all[hour] = hourly_all.get(hour, 0) + 1
            if len(found) > 0 or code in ["401", "403", "404"]:
                hourly_threat[hour] = hourly_threat.get(hour, 0) + 1

    # Score every IP with the multi-layer engine
    ips = {}
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for ip in ip_info:
        info = ip_info[ip]
        result = score_entity(info["types"], info["auth_fails"], len(info["missing_paths"]), feed_lookup(ip))
        ips[ip] = {
            "ip": ip,
            "requests": info["requests"],
            "failed": info["failed"],
            "result": result,
        }
        counts[result["level"]] = counts[result["level"]] + 1

    # Risk index: Critical IP = 20 pts, High = 10 pts, Medium = 5 pts (max 100)
    risk_index = counts["CRITICAL"] * 20 + counts["HIGH"] * 10 + counts["MEDIUM"] * 5
    if risk_index > 100:
        risk_index = 100

    return {
        "total_logs": len(logs),
        "ips": ips,
        "counts": counts,
        "status_counts": status_counts,
        "hourly_all": hourly_all,
        "hourly_threat": hourly_threat,
        "risk_index": risk_index,
        "health": 100 - risk_index,
    }


@st.cache_data(show_spinner="Analysing logs...", max_entries=3)
def cached_summary(log_stamp, intel_stamp):
    """build_summary() with a cache: it only re-runs when the log file or the feeds change."""
    return build_summary(read_logs())


def get_category(result):
    """Short label describing what kind of threat an IP is."""
    if result["feed"] is not None:
        return result["feed"]["category"]
    if len(result["vectors"]) > 0:
        return result["vectors"][0]["Vector"]
    return "Clean traffic"


def get_tactics(result):
    """Unique MITRE tactics of a result, as a comma separated text."""
    tactics = []
    for vector in result["vectors"]:
        if vector["MITRE Tactic"] not in tactics:
            tactics.append(vector["MITRE Tactic"])
    if len(tactics) == 0:
        return "-"
    return ", ".join(tactics)


def get_vector_names(result):
    names = []
    for vector in result["vectors"]:
        names.append(vector["Vector"])
    return names


def get_ip_rows(summary, min_score):
    """One dictionary per IP whose score is at least min_score."""
    rows = []
    for ip in summary["ips"]:
        record = summary["ips"][ip]
        result = record["result"]
        if result["score"] >= min_score:
            abuse = 0
            vt = 0
            if result["feed"] is not None:
                abuse = result["feed"]["abuse"]
                vt = result["feed"]["vt"]
            geo = geo_lookup(ip)
            rows.append({
                "IP": ip,
                "Origin (simulated)": geo["country"],
                "Lat": geo["lat"],
                "Lon": geo["lon"],
                "Category": get_category(result),
                "Risk Score": result["score"],
                "Level": result["level"],
                "Marker Size": max(result["score"], 8),
                "Requests": record["requests"],
                "Failed (401/403/404)": record["failed"],
                "Vectors": ", ".join(get_vector_names(result)),
                "MITRE Tactics": get_tactics(result),
                "Feed Confidence %": abuse,
                "Feeds Listing": vt,
            })
    return rows


# ---------------------------------------------------------------
# 7. SESSION STATE (scan history and simulator flags)
# ---------------------------------------------------------------
def setup_state():
    """Create session variables once per browser session."""
    if "history" not in st.session_state:
        st.session_state["history"] = []
    if "target_box" not in st.session_state:
        st.session_state["target_box"] = ""
    if "scan_now" not in st.session_state:
        st.session_state["scan_now"] = False
    if "sim_auth" not in st.session_state:
        st.session_state["sim_auth"] = 0
    if "sim_ports" not in st.session_state:
        st.session_state["sim_ports"] = 0
    if "preset_used" not in st.session_state:
        st.session_state["preset_used"] = False
    if "live_events" not in st.session_state:
        st.session_state["live_events"] = []
    if "pending_sound" not in st.session_state:
        st.session_state["pending_sound"] = None
    if "page" not in st.session_state:
        st.session_state["page"] = PAGES[0]
    if "auth" not in st.session_state:
        st.session_state["auth"] = False
    if "fail_count" not in st.session_state:
        st.session_state["fail_count"] = 0
    if "locked_until" not in st.session_state:
        st.session_state["locked_until"] = 0.0
    if "last_active" not in st.session_state:
        st.session_state["last_active"] = time.time()


def go_page(name):
    """Callback of a sidebar navigation button."""
    st.session_state["page"] = name


def run_preset(name):
    """Callback of a simulator button: fill the box and request a scan."""
    st.session_state["target_box"] = PRESETS[name]["target"]
    st.session_state["sim_auth"] = PRESETS[name]["auth_fails"]
    st.session_state["sim_ports"] = PRESETS[name]["ports"]
    st.session_state["preset_used"] = True
    st.session_state["scan_now"] = True


def add_to_history(target, result, source):
    """Save one scan as a dictionary (= one table row)."""
    st.session_state["history"].append({
        "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Target Checked": target,
        "Risk Score": result["score"],
        "Threat Level": result["level"],
        "Vectors": ", ".join(get_vector_names(result)),
        "Source": source,
    })


def clear_history():
    st.session_state["history"] = []


def history_dataframe():
    """History as a table with coloured level badges."""
    df = pd.DataFrame(st.session_state["history"])
    df["Threat Level"] = df["Threat Level"].map(LEVEL_EMOJI)
    return df


# ---------------------------------------------------------------
# 8. CHART BUILDERS (Plotly)
# ---------------------------------------------------------------
def style_fig(fig, height=330):
    """Apply the clean dark look to any Plotly figure."""
    top = 24
    if fig.layout.title is not None and fig.layout.title.text:
        top = 50
    fig.update_layout(
        template="plotly_dark",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color=TEXT, family="Inter, Segoe UI, Arial, sans-serif", size=12),
        title_font=dict(size=15, color=TEXT),
        margin=dict(l=10, r=10, t=top, b=10),
        height=height,
        legend=dict(bgcolor="rgba(0,0,0,0)"),
        hoverlabel=dict(bgcolor=PANEL, font_color=TEXT, bordercolor=ACCENT),
    )
    fig.update_xaxes(gridcolor=GRID, zerolinecolor=GRID, linecolor=GRID)
    fig.update_yaxes(gridcolor=GRID, zerolinecolor=GRID, linecolor=GRID)
    return fig


# Newer Streamlit uses width="stretch"; older versions use use_container_width=True
PLOTLY_HAS_WIDTH = "width" in inspect.signature(st.plotly_chart).parameters


def show_chart(fig, key):
    """Draw a Plotly chart full width (works on old and new Streamlit)."""
    if PLOTLY_HAS_WIDTH:
        st.plotly_chart(fig, width="stretch", key=key, theme=None, config={"displayModeBar": False})
    else:
        st.plotly_chart(fig, use_container_width=True, key=key, theme=None, config={"displayModeBar": False})


def index_color(value):
    """Green / yellow / red depending on the value."""
    if value >= 70:
        return LEVEL_COLORS["CRITICAL"]
    elif value >= 40:
        return LEVEL_COLORS["MEDIUM"]
    return LEVEL_COLORS["LOW"]


def make_gauge(value, title, color):
    """Gauge chart from 0 to 100."""
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=value,
        title={"text": title, "font": {"size": 13, "color": MUTED}},
        number={"font": {"color": TEXT, "size": 42}},
        gauge={
            "axis": {"range": [0, 100], "tickcolor": MUTED, "tickfont": {"size": 10}},
            "bar": {"color": color, "thickness": 0.3},
            "bgcolor": "rgba(0,0,0,0)",
            "borderwidth": 0,
            "steps": [
                {"range": [0, 40], "color": "rgba(34,197,94,0.16)"},
                {"range": [40, 70], "color": "rgba(234,179,8,0.16)"},
                {"range": [70, 100], "color": "rgba(239,68,68,0.20)"},
            ],
        },
    ))
    return style_fig(fig, 270)


def make_donut(summary):
    """Donut chart: how many IPs are CRITICAL / HIGH / MEDIUM / LOW."""
    labels = []
    values = []
    colors = []
    for level in LEVEL_ORDER:
        labels.append(LEVEL_LABELS[level])
        values.append(summary["counts"][level])
        colors.append(LEVEL_COLORS[level])
    fig = go.Figure(go.Pie(
        labels=labels, values=values, hole=0.7,
        marker=dict(colors=colors, line=dict(color=BG, width=3)),
        textinfo="none", sort=False,
    ))
    fig.update_layout(
        showlegend=True, legend=dict(orientation="h", y=-0.08, x=0.5, xanchor="center"),
        annotations=[dict(text=str(len(summary["ips"])) + "<br><span style='font-size:12px'>IPs</span>", x=0.5, y=0.5,
                          showarrow=False, font=dict(size=26, color=TEXT))],
    )
    return style_fig(fig, 290)


def vector_counts(summary):
    """How many IPs show each attack technique (used by the bars and the radar)."""
    counts = {}
    for name in ATTACK_TYPES:
        counts[name] = 0
    for ip in summary["ips"]:
        for vector in summary["ips"][ip]["result"]["vectors"]:
            counts[vector["Vector"]] = counts.get(vector["Vector"], 0) + 1
    return counts


def make_radar(summary):
    """Radar chart: detections per attack technique."""
    counts = vector_counts(summary)
    names = list(counts.keys())
    values = [counts[name] for name in names]
    fig = go.Figure(go.Scatterpolar(
        r=values + [values[0]], theta=names + [names[0]], fill="toself",
        line=dict(color=ACCENT, width=2), fillcolor=hex_to_rgba(ACCENT, 0.25),
        marker=dict(size=6, color=ACCENT2),
    ))
    fig.update_layout(
        showlegend=False,
        polar=dict(
            bgcolor="rgba(0,0,0,0)",
            radialaxis=dict(gridcolor=GRID, linecolor=GRID, tickfont=dict(size=9, color=MUTED), showline=False),
            angularaxis=dict(gridcolor=GRID, linecolor=GRID, tickfont=dict(size=10, color=TEXT)),
        ),
    )
    fig = style_fig(fig, 290)
    fig.update_layout(margin=dict(l=70, r=70, t=24, b=24))
    return fig


def make_timeline(summary):
    """Smooth area chart: all requests versus threat events for every hour of the day."""
    hours = []
    all_list = []
    threat_list = []
    for h in range(24):
        hour = str(h).zfill(2)
        hours.append(hour + ":00")
        all_list.append(summary["hourly_all"].get(hour, 0))
        threat_list.append(summary["hourly_threat"].get(hour, 0))
    fig = go.Figure()
    fig.add_trace(go.Scatter(x=hours, y=all_list, name="All requests", mode="lines",
                             line=dict(color=ACCENT2, width=2.5, shape="spline"),
                             fill="tozeroy", fillcolor=hex_to_rgba(ACCENT2, 0.12)))
    fig.add_trace(go.Scatter(x=hours, y=threat_list, name="Threat events", mode="lines+markers",
                             line=dict(color=ACCENT, width=3, shape="spline"), marker=dict(size=6),
                             fill="tozeroy", fillcolor=hex_to_rgba(ACCENT, 0.20)))
    fig.update_layout(legend=dict(orientation="h", y=1.14, x=0), yaxis_title=None)
    return style_fig(fig, 300)


def make_layer_chart(result):
    """Horizontal bars: points from each of the scoring layers."""
    caps = {"Pattern Matching": PATTERN_CAP, "Anomaly Detection": ANOMALY_CAP,
            "IP Reputation": REPUTATION_CAP, "URL Forensics": URL_CAP}
    names = list(result["layers"].keys())
    values = []
    labels = []
    for name in names:
        values.append(result["layers"][name])
        labels.append(str(result["layers"][name]) + " / " + str(caps[name]))
    fig = go.Figure(go.Bar(
        x=values, y=names, orientation="h", text=labels, textposition="auto",
        marker_color=[ACCENT, ACCENT2, ACCENT3, "#f59e0b"],
    ))
    fig.update_layout(xaxis=dict(range=[0, 85]), yaxis=dict(autorange="reversed"))
    return style_fig(fig, 280)


def make_sunburst(summary):
    """Sunburst: MITRE tactic -> attack type -> IP (size = risk score)."""
    rows = []
    for ip in summary["ips"]:
        result = summary["ips"][ip]["result"]
        for vector in result["vectors"]:
            rows.append({
                "Tactic": vector["MITRE Tactic"],
                "Attack Type": vector["Vector"],
                "IP": ip,
                "Score": max(result["score"], 1),
            })
    if len(rows) == 0:
        return None
    fig = px.sunburst(pd.DataFrame(rows), path=["Tactic", "Attack Type", "IP"], values="Score",
                      color="Tactic", color_discrete_sequence=PALETTE)
    fig.update_traces(marker=dict(line=dict(color=BG, width=2)))
    return style_fig(fig, 480)


def make_geo_map(df):
    """World map of simulated attacker origins (bubble size = risk score)."""
    fig = px.scatter_geo(
        df, lat="Lat", lon="Lon", size="Marker Size", color="Level",
        hover_name="IP", hover_data={"Origin (simulated)": True, "Category": True,
                                      "Risk Score": True, "Lat": False, "Lon": False, "Marker Size": False},
        color_discrete_map=LEVEL_COLORS, category_orders={"Level": LEVEL_ORDER},
        projection="natural earth",
    )
    land, ocean, country, coast = hex_to_rgba(ACCENT3, 0.22), "rgba(0,0,0,0)", BG, hex_to_rgba(ACCENT3, 0.35)
    fig.update_geos(bgcolor="rgba(0,0,0,0)", landcolor=land, showland=True,
                    showcountries=True, countrycolor=country, showocean=True,
                    oceancolor=ocean, showframe=False, coastlinecolor=coast)
    return style_fig(fig, 430)


# ---------------------------------------------------------------
# 9. HTML COMPONENTS (badges, cards, banner)
# ---------------------------------------------------------------
def badge_html(level):
    """Status badge (CRITICAL / HIGH / MEDIUM / LOW)."""
    return '<span class="badge ' + level.lower() + '">' + LEVEL_LABELS[level] + '</span>'


def risk_card_html(result):
    """Verdict card for the scanner result (like a VirusTotal summary)."""
    level = result["level"]
    flagged = 0
    for name in result["layers"]:
        if result["layers"][name] > 0:
            flagged = flagged + 1
    return ('<div class="risk-card ' + level.lower() + '">'
            '<div class="risk-score" style="color:' + LEVEL_COLORS[level] + ';">' + str(result["score"]) + '<span class="risk-max">/ 100</span></div>'
            '<div><div>' + badge_html(level) + '<span class="risk-note">' + str(flagged) + ' of ' + str(len(result["layers"])) + ' detection layers flagged this target</span></div>'
            '<div class="risk-target">' + html.escape(result["target"]) + '</div></div></div>')


def side_label_html(text):
    """Small section title used in the sidebar."""
    return '<div class="side-label">' + text + '</div>'


def threat_level_name(index):
    """Risk index -> (name, colour)."""
    if index >= 75:
        return "Critical", LEVEL_COLORS["CRITICAL"]
    elif index >= 50:
        return "Severe", LEVEL_COLORS["HIGH"]
    elif index >= 25:
        return "Elevated", LEVEL_COLORS["MEDIUM"]
    return "Normal", LEVEL_COLORS["LOW"]


def sidebar_profile_html(summary):
    """Brand row, profile photo and threat level indicator at the top of the sidebar."""
    name, color = threat_level_name(summary["risk_index"])
    width = max(summary["risk_index"], 3)
    return ('<div class="brand"><div class="brand-logo">TV</div><div>'
            '<div class="brand-name">ThreatVision Pro</div><div class="brand-sub">Threat Intelligence Platform</div></div></div>'
            '<div class="profile"><div class="avatar-ring">' + avatar_html() + '<span class="online"></span></div>'
            '<div class="p-name">' + html.escape(DISPLAY_NAME) + '</div>'
            '<div class="p-role">' + html.escape(ROLE_TEXT) + '</div></div>'
            '<div class="risk-box"><div class="risk-row"><span>Threat level</span><b style="color:' + color + ';">' + name + '</b></div>'
            '<div class="risk-bar"><div class="risk-fill" style="width:' + str(width) + '%;background:' + color + ';"></div></div>'
            '<div class="risk-foot">Risk index ' + str(summary["risk_index"]) + ' / 100</div></div>')


def sidebar_stats_html(summary):
    """Small system status panel at the bottom of the sidebar."""
    last_scan = "-"
    if len(st.session_state["history"]) > 0:
        last_scan = st.session_state["history"][-1]["Timestamp"][11:]
    return ('<div class="side-stat">'
            '<div>Mode <b>' + mode_name() + '</b></div>'
            '<div>Log lines <b>' + str(summary["total_logs"]) + '</b></div>'
            '<div>Unique IPs <b>' + str(len(summary["ips"])) + '</b></div>'
            '<div>Session scans <b>' + str(len(st.session_state["history"])) + '</b></div>'
            '<div>Last scan <b>' + last_scan + '</b></div></div>'
            '<div class="side-foot">ThreatVision Pro v2.0</div>')


def mode_name():
    """Short name of the current intelligence mode."""
    if INTEL_MODE == "real":
        return "Real-world"
    return "Demo"


def page_header_html(title, log_count):
    """Top bar: breadcrumb, page title, live status and the signed-in user."""
    now = datetime.now().strftime("%d %b %Y · %H:%M")
    return ('<div class="topbar"><div><div class="crumb">Dashboard <span>/ ' + html.escape(title) + '</span></div>'
            '<div class="page-title">' + html.escape(title) + '</div></div>'
            '<div class="top-right"><span class="chip"><span class="live-dot"></span>Live · ' + str(log_count) + ' log lines · '
            + mode_name() + ' mode</span><span class="chip">' + now + '</span>'
            '<span class="user-chip">' + avatar_html() + html.escape(DISPLAY_NAME) + '</span></div></div>')


def alert_feed_html(summary, min_score):
    """Live alert feed: the highest scoring IPs (score 40+)."""
    rows = get_ip_rows(summary, max(min_score, 40))
    if len(rows) == 0:
        return '<div class="alert-item medium">No active alerts for this filter.</div>'
    rows = sorted(rows, key=lambda row: row["Risk Score"], reverse=True)
    text = ""
    for row in rows[:5]:
        level = row["Level"]
        text = text + ('<div class="alert-item ' + level.lower() + '">'
                       '<span class="sc" style="color:' + LEVEL_COLORS[level] + ';">' + str(row["Risk Score"]) + '</span>'
                       '<span class="ip">' + html.escape(row["IP"]) + '</span><br>'
                       + html.escape(row["Category"]) + ' · ' + html.escape(row["MITRE Tactics"]) + '</div>')
    return text


def kill_chain_html(tactic_counts):
    """MITRE tactic strip: red boxes where detections exist."""
    text = '<div class="kc-row">'
    for tactic in TACTIC_ORDER:
        count = tactic_counts.get(tactic, 0)
        css = "kc-box"
        if count > 0:
            css = "kc-box active"
        text = text + '<div class="' + css + '"><span class="num">' + str(count) + '</span>' + tactic.upper() + '</div>'
    return text + '</div>'


def kpi_cards_html(summary):
    """Five ring cards for the top of the Overview page."""
    total_ips = max(len(summary["ips"]), 1)
    counts = summary["counts"]
    normal = summary["status_counts"].get("200", 0)
    normal_percent = round(normal * 100 / max(summary["total_logs"], 1))
    flagged = counts["CRITICAL"] + counts["HIGH"] + counts["MEDIUM"]
    if summary["health"] >= 70:
        health_colors = ("#22c55e", "#a3e635")
        health_text = "Healthy"
    elif summary["health"] >= 40:
        health_colors = ("#eab308", "#f97316")
        health_text = "Needs attention"
    else:
        health_colors = ("#ef4444", "#f97316")
        health_text = "Under attack"
    return [
        ring_card_html("Logs processed", summary["total_logs"], normal_percent, str(normal_percent) + "% normal traffic"),
        ring_card_html("Unique IPs", len(summary["ips"]), round(flagged * 100 / total_ips), str(flagged) + " need attention"),
        ring_card_html("Critical", counts["CRITICAL"], round(counts["CRITICAL"] * 100 / total_ips), "of all IPs", ("#ef4444", "#f97316")),
        ring_card_html("High", counts["HIGH"], round(counts["HIGH"] * 100 / total_ips), "of all IPs", ("#f97316", "#eab308")),
        ring_card_html("Security health", str(summary["health"]) + "%", summary["health"], health_text, health_colors),
    ]


def kpi_strip_html(summary):
    """Small row of numbers for the pages that are not the Overview."""
    counts = summary["counts"]
    return ('<div class="kpi-strip"><span class="chip">Logs <b>' + str(summary["total_logs"]) + '</b></span>'
            '<span class="chip">Unique IPs <b>' + str(len(summary["ips"])) + '</b></span>'
            '<span class="chip">Critical <b style="color:' + LEVEL_COLORS["CRITICAL"] + ';">' + str(counts["CRITICAL"]) + '</b></span>'
            '<span class="chip">High <b style="color:' + LEVEL_COLORS["HIGH"] + ';">' + str(counts["HIGH"]) + '</b></span>'
            '<span class="chip">Health <b>' + str(summary["health"]) + '%</b></span></div>')


def top_techniques_html(summary):
    """Gradient bars: the most common attack techniques."""
    counts = vector_counts(summary)
    ordered = sorted(counts.items(), key=lambda item: item[1], reverse=True)[:5]
    biggest = max([item[1] for item in ordered] + [1])
    bars = ""
    for name, number in ordered:
        bars = bars + gbar_html(name, number, biggest)
    return '<div class="card"><div class="card-title">Top attack techniques</div>' + bars + '</div>'


def status_bars_html(summary):
    """LED-style bars: HTTP status codes, normal versus malicious."""
    codes = summary["status_counts"]
    rows = [("200 OK", "200", ("#22c55e", "#a3e635")), ("401 Unauthorized", "401", ("#ef4444", "#f97316")),
            ("403 Forbidden", "403", ("#ef4444", "#f97316")), ("404 Not Found", "404", ("#eab308", "#f97316")),
            ("500 Server error", "500", (ACCENT3, ACCENT2))]
    biggest = max([codes.get(item[1], 0) for item in rows] + [1])
    bars = ""
    for label, code, colors in rows:
        bars = bars + segbar_html(label, codes.get(code, 0), biggest, colors)
    return '<div class="card"><div class="card-title">HTTP status codes</div>' + bars + '</div>'


# ---------------------------------------------------------------
# 10. PAGES
# ---------------------------------------------------------------
def page_overview(summary, min_score):
    if summary["total_logs"] == 0:
        st.info("No log data yet. Click 'Create sample server_logs.txt' in the sidebar.")
        return

    columns = st.columns(5)
    for column, card in zip(columns, kpi_cards_html(summary)):
        column.markdown(card, unsafe_allow_html=True)

    left, middle, right = st.columns([1.5, 1.1, 1.0])
    with left:
        st.markdown(executive_summary_html(summary), unsafe_allow_html=True)
    with middle:
        st.markdown(top_techniques_html(summary), unsafe_allow_html=True)
    with right:
        chart_card("Organisation risk index", make_gauge(summary["risk_index"], "", index_color(summary["risk_index"])), "gauge_overview")

    wide, narrow = st.columns([2, 1])
    with wide:
        chart_card("Attack frequency over 24 hours", make_timeline(summary), "timeline_overview")
    with narrow:
        st.markdown(status_bars_html(summary), unsafe_allow_html=True)

    c1, c2, c3 = st.columns(3)
    with c1:
        chart_card("Severity distribution", make_donut(summary), "donut_overview")
    with c2:
        chart_card("Attack technique radar", make_radar(summary), "radar_overview")
    with c3:
        st.markdown('<div class="card"><div class="card-title">Live alert feed</div>' + alert_feed_html(summary, min_score) + '</div>',
                    unsafe_allow_html=True)

    st.caption("Risk index = 20 points per CRITICAL IP + 10 per HIGH + 5 per MEDIUM (maximum 100). Security health = 100 - risk index.")
    if INTEL_MODE == "real":
        st.caption("Real-world mode: scores use open threat feeds. Feeds are partial and delayed, so no tool "
                   "can promise to catch every malicious IP or URL.")


def show_response_actions(result):
    """Mitigations and firewall rules for a scan result."""
    st.markdown("#### Recommended Mitigations")
    for step in build_mitigations(result):
        st.markdown("- " + step)

    st.markdown("#### Firewall Rules")
    rules = build_firewall_rules(result)
    if len(rules) == 0:
        st.caption("No firewall rule needed for this target.")
    for rule in rules:
        st.caption(rule[0])
        code_block(rule[1])


def show_scan_result(scan):
    """Full breakdown card for the last scan."""
    result = scan["result"]
    st.markdown(risk_card_html(result), unsafe_allow_html=True)

    col1, col2 = st.columns(2)
    with col1:
        chart_card("Threat score", make_gauge(result["score"], "", LEVEL_COLORS[result["level"]]), "gauge_scan")
    with col2:
        chart_card("Risk score breakdown (4 layers)", make_layer_chart(result), "layers_scan")

    st.markdown("#### Matched Attack Vectors")
    if len(result["vectors"]) == 0:
        st.success("No attack vectors matched.")
    else:
        render_table(pd.DataFrame(result["vectors"]), hide_index=True)
    if result["sim_auth"] > 0:
        st.caption("Includes " + str(result["sim_auth"]) + " simulated failed logins (attack simulator).")
    if result["sim_ports"] > 0:
        st.caption("Includes " + str(result["sim_ports"]) + " simulated probed ports (attack simulator).")

    show_forensics_panel(result)

    if INTEL_MODE == "real":
        st.markdown("#### Threat Feed Intelligence (open feeds)")
    else:
        st.markdown("#### Threat Feed Intelligence (simulated AbuseIPDB / VirusTotal)")
    feed = result["feed"]
    if feed is None:
        if INTEL_MODE == "real":
            st.caption("Not listed in the loaded open feeds. This does NOT prove it is safe - feeds are partial.")
        else:
            st.caption("No hits in the simulated threat feeds.")
    elif feed.get("real"):
        f1, f2, f3, f4 = st.columns(4)
        f1.metric("Feed confidence", str(feed["abuse"]) + "%")
        f2.metric("Feeds listing it", feed["vt"])
        f3.metric("Origin", feed["country"])
        f4.metric("Category", feed["category"])
        st.caption("Sources: " + ", ".join(feed["sources"]))
    else:
        f1, f2, f3, f4 = st.columns(4)
        f1.metric("AbuseIPDB Confidence (simulated)", str(feed["abuse"]) + "%")
        f2.metric("VirusTotal Detections (simulated)", str(feed["vt"]) + " / 70")
        f3.metric("Origin", feed["country"])
        f4.metric("Category", feed["category"])

    show_live_lookups(result)
    show_osint_panel(result)

    with st.expander("Response: mitigations and firewall rules", expanded=True):
        show_response_actions(result)

    report_name = re.sub(r"[^a-z0-9]+", "_", result["target"])[:40].strip("_")
    st.download_button("Download investigation report (JSON)",
                       data=json.dumps(build_investigation_report(result), indent=2, default=str),
                       file_name="investigation_" + report_name + ".json", mime="application/json")


def page_scanner(logs):

    if INTEL_MODE == "demo":
        with st.expander("Attack simulator (demo presets)"):
            names = list(PRESETS.keys())
            for start in range(0, len(names), 5):
                columns = st.columns(5)
                for offset in range(5):
                    if start + offset < len(names):
                        columns[offset].button(names[start + offset], on_click=run_preset,
                                               args=(names[start + offset],), key="preset_" + str(start + offset))


    if INTEL_MODE == "real":
        st.markdown("**Real-world examples (taken from the live open feeds)**")
        real_cols = st.columns(4)
        real_cols[0].button("Real botnet C2 IP", on_click=run_real_example, args=("c2",), key="real_c2")
        real_cols[1].button("Real attacker IP", on_click=run_real_example, args=("ip",), key="real_ip")
        real_cols[2].button("Real phishing domain", on_click=run_real_example, args=("domain",), key="real_domain")
        real_cols[3].button("Real malware URL", on_click=run_real_example, args=("url",), key="real_url")
        st.caption("These are real malicious indicators. Only their text is checked - never open them in a browser.")
    notice = st.session_state.get("notice", "")
    if notice != "":
        st.warning(notice)
        st.session_state["notice"] = ""

    user_text = st.text_input("Target URL or IP address", key="target_box",
                              placeholder="e.g. 203.0.113.45  |  http://phishing-site.com/login  |  /admin")

    do_scan = False
    sim_auth = 0
    sim_ports = 0
    source = "Manual"

    if st.session_state["scan_now"]:              # a simulator button was clicked
        do_scan = True
        sim_auth = st.session_state["sim_auth"]
        sim_ports = st.session_state["sim_ports"]
        source = "Simulator"
        st.session_state["scan_now"] = False
        st.session_state["sim_auth"] = 0
        st.session_state["sim_ports"] = 0

    if st.button("Scan Target", type="primary"):
        do_scan = True
        sim_auth = 0
        sim_ports = 0
        source = "Manual"

    if do_scan:
        target = clean_input(user_text)
        if target == "":
            st.warning("Please enter a URL or IP first.")
        else:
            result = analyze_target(target, logs, sim_auth, sim_ports)
            st.session_state["last_scan"] = {"result": result}
            add_to_history(target, result, source)
            queue_sound(result["level"], sound_text(result["level"], result["score"]))
            write_audit("Scan | " + target + " | score " + str(result["score"]) + " | " + result["level"] + " | " + source)

    if "last_scan" in st.session_state:
        show_scan_result(st.session_state["last_scan"])
    else:
        st.info("Type a target and press Scan Target, or click one of the attack simulator buttons.")


def page_geo(summary, min_score):
    rows = get_ip_rows(summary, min_score)
    if len(rows) == 0:
        st.info("No IPs match the selected severity filter.")
        return

    df = pd.DataFrame(rows).sort_values("Risk Score", ascending=False)

    st.markdown("#### Top Malicious IPs")
    table = df.copy()
    table["Threat Level"] = table["Level"].map(LEVEL_EMOJI)
    table = table[["IP", "Origin (simulated)", "Category", "Risk Score", "Threat Level",
                   "MITRE Tactics", "Feed Confidence %", "Feeds Listing"]]
    if len(table) > 200:
        st.caption("Showing the top 200 of " + str(len(table)) + " IPs. Use the severity filter in the sidebar to narrow down.")
        table = table.head(200)
    render_table(table, hide_index=True,
                 column_config={"Risk Score": st.column_config.ProgressColumn("Risk Score", min_value=0, max_value=100, format="%d")})

    map_df = df[df["Lat"].notna()]
    left, right = st.columns([2, 1])
    with left:
        if len(map_df) == 0:
            st.info("Only internal IPs match this filter, so there is nothing to draw on the map.")
        else:
            chart_card("Attack origins (simulated)", make_geo_map(map_df), "geo_map")
    with right:
        by_country = df.groupby("Origin (simulated)")["Risk Score"].max().reset_index()
        fig = px.bar(by_country, x="Risk Score", y="Origin (simulated)", orientation="h",
                     color="Risk Score",
                     color_continuous_scale=["#22c55e", "#eab308", "#ef4444"], range_color=[0, 100])
        fig.update_layout(coloraxis_showscale=False, yaxis_title="")
        chart_card("Highest threat score by origin", style_fig(fig, 430), "geo_country")

    if INTEL_MODE == "real":
        show_real_intel_panel(summary)
        return

    st.markdown("#### Threat Feed Simulator (AbuseIPDB / VirusTotal)")
    feed_rows = []
    for key in THREAT_FEED:
        entry = THREAT_FEED[key]
        feed_rows.append({
            "Indicator": key,
            "AbuseIPDB Confidence %": entry["abuse"],
            "VirusTotal Detections": entry["vt"],
            "Country": entry["country"],
            "Category": entry["category"],
        })
    render_table(pd.DataFrame(feed_rows), hide_index=True)
    st.caption("Origins and feed data are simulated for demonstration. Unknown public IPs get a "
               "country calculated from their numbers; internal IPs are not drawn on the map.")


def page_mitre(summary):
    if summary["total_logs"] == 0:
        st.info("No log data yet. Click 'Create sample server_logs.txt' in the sidebar.")
        return

    # Count how many IPs show each attack type
    type_counts = {}
    type_ips = {}
    for name in ATTACK_TYPES:
        type_counts[name] = 0
        type_ips[name] = []
    for ip in summary["ips"]:
        for name in get_vector_names(summary["ips"][ip]["result"]):
            type_counts[name] = type_counts[name] + 1
            type_ips[name].append(ip)

    # Add up the detections for each tactic
    tactic_counts = {}
    for name in ATTACK_TYPES:
        tactic = ATTACK_TYPES[name]["tactic"]
        tactic_counts[tactic] = tactic_counts.get(tactic, 0) + type_counts[name]

    st.markdown("**Kill-chain view (detections per tactic)**")
    st.markdown(kill_chain_html(tactic_counts), unsafe_allow_html=True)

    rows = []
    for name in ATTACK_TYPES:
        info = ATTACK_TYPES[name]
        rows.append({
            "Attack Type": name,
            "MITRE Tactic": info["tactic"],
            "Technique ID": info["tech_id"],
            "Technique": info["technique"],
            "Detections (IPs)": type_counts[name],
            "IPs": ", ".join(type_ips[name]),
        })
    df = pd.DataFrame(rows)

    left, right = st.columns([3, 2])
    with left:
        st.markdown("#### ATT&CK Mapping Table")
        render_table(df, hide_index=True)
    with right:
        active = df[df["Detections (IPs)"] > 0]
        if len(active) == 0:
            st.success("No attack techniques detected.")
        else:
            fig = px.bar(active, x="Detections (IPs)", y="Attack Type", orientation="h", color="MITRE Tactic",
                         text="Detections (IPs)",
                         color_discrete_sequence=PALETTE)
            fig.update_layout(yaxis_title="")
            chart_card("Detections by attack type", style_fig(fig, 340), "mitre_bar")

    sunburst = make_sunburst(summary)
    if sunburst is not None:
        chart_card("Threat surface: tactic, attack type, IP", sunburst, "mitre_sunburst")

    st.markdown("#### Inspect one IP")
    suspicious = []
    for ip in summary["ips"]:
        if len(summary["ips"][ip]["result"]["vectors"]) > 0:
            suspicious.append(ip)
    if len(suspicious) == 0:
        st.caption("No IP has matched an attack vector.")
    else:
        chosen = st.selectbox("Choose an IP", suspicious)
        result = summary["ips"][chosen]["result"]
        st.markdown(badge_html(result["level"]) + " &nbsp; Score **" + str(result["score"]) + "/100**", unsafe_allow_html=True)
        render_table(pd.DataFrame(result["vectors"]), hide_index=True)


def build_export_table(summary):
    """Flat table (one row per IP) used for CSV export."""
    rows = []
    for ip in summary["ips"]:
        record = summary["ips"][ip]
        result = record["result"]
        abuse = 0
        vt = 0
        if result["feed"] is not None:
            abuse = result["feed"]["abuse"]
            vt = result["feed"]["vt"]
        rows.append({
            "IP": ip,
            "Origin (simulated)": geo_lookup(ip)["country"],
            "Category": get_category(result),
            "Risk Score": result["score"],
            "Threat Level": result["level"],
            "Pattern Score": result["layers"]["Pattern Matching"],
            "Anomaly Score": result["layers"]["Anomaly Detection"],
            "Reputation Score": result["layers"]["IP Reputation"],
            "Attack Vectors": "; ".join(get_vector_names(result)),
            "MITRE Tactics": get_tactics(result),
            "Requests": record["requests"],
            "Failed Requests": record["failed"],
            "Feed Confidence %": abuse,
            "Feeds Listing": vt,
        })
    return pd.DataFrame(rows)


def build_json_report(summary):
    """Full threat report as a dictionary (exported as JSON)."""
    return {
        "report": "ThreatVision Pro - Threat Report",
        "generated_at": str(datetime.now()),
        "intelligence_mode": INTEL_MODE,
        "feeds": INTEL_DATA.get("status", []),
        "summary": {
            "total_logs": summary["total_logs"],
            "unique_ips": len(summary["ips"]),
            "critical": summary["counts"]["CRITICAL"],
            "high": summary["counts"]["HIGH"],
            "medium": summary["counts"]["MEDIUM"],
            "low": summary["counts"]["LOW"],
            "risk_index": summary["risk_index"],
            "security_health_percent": summary["health"],
            "status_codes": summary["status_counts"],
        },
        "ip_threats": build_export_table(summary).to_dict(orient="records"),
        "scan_history": st.session_state["history"],
    }


def page_reports(summary, logs):

    st.markdown("#### Scan History (this session)")
    if len(st.session_state["history"]) == 0:
        st.info("No scans yet. Use the Live Scanner page.")
    else:
        render_table(history_dataframe(), hide_index=True,
                     column_config={"Risk Score": st.column_config.ProgressColumn("Risk Score", min_value=0, max_value=100, format="%d")})
    st.button("Clear History", on_click=clear_history)

    st.markdown("#### One-Click Export")
    if summary["total_logs"] == 0:
        st.info("Exports are available once server_logs.txt has data.")
    else:
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_text = json.dumps(build_json_report(summary), indent=2)
        csv_text = build_export_table(summary).to_csv(index=False)
        report_text = read_text_file(REPORT_FILE)
        audit_text = read_text_file(AUDIT_FILE)

        c1, c2, c3, c4 = st.columns(4)
        c1.download_button("JSON Report", data=json_text, file_name="threat_report_" + stamp + ".json", mime="application/json")
        c2.download_button("CSV Report", data=csv_text, file_name="threat_report_" + stamp + ".csv", mime="text/csv")
        c3.download_button("threat_report.txt", data=report_text, file_name="threat_report.txt", mime="text/plain")
        c4.download_button("security_audit.log", data=audit_text, file_name="security_audit.log", mime="text/plain")

        with st.expander("Preview JSON report"):
            code_block(json.dumps(build_json_report(summary), indent=2, default=str), max_chars=8000)

    st.markdown("#### Security Audit Log (latest 20 entries)")
    audit_text = read_text_file(AUDIT_FILE)
    if audit_text == "":
        st.caption("Audit log is empty.")
    else:
        audit_lines = audit_text.strip().split("\n")
        code_block("\n".join(audit_lines[-20:]))

    with st.expander("View raw server_logs.txt"):
        if len(logs) == 0:
            st.caption("No log lines.")
        else:
            code_block("\n".join(logs[:300]))
            if len(logs) > 300:
                st.caption("Showing the first 300 of " + str(len(logs)) + " lines.")


# ---------------------------------------------------------------
# 11. SOUND ALERTS (beeps + voice)
# ---------------------------------------------------------------
# Python only decides WHAT to play. A tiny JavaScript (Web Audio + Speech Synthesis)
# runs inside the browser and makes the sound. Browsers only allow sound after the
# user has clicked something on the page, so the first click unlocks it.
SOUND_STYLES = ["Beeps", "Voice", "Both"]

# Each level has its own beep pattern: [frequency in Hz, length in seconds]
SOUND_PATTERNS = {
    "CRITICAL": {"wave": "square", "beeps": [[880, 0.16], [660, 0.16], [880, 0.16], [660, 0.16]]},
    "HIGH": {"wave": "square", "beeps": [[740, 0.20], [740, 0.20]]},
    "MEDIUM": {"wave": "sine", "beeps": [[520, 0.25]]},
    "LOW": {"wave": "sine", "beeps": [[660, 0.12], [880, 0.18]]},
}

SOUND_WORDS = {
    "CRITICAL": "Critical threat detected",
    "HIGH": "High risk detected",
    "MEDIUM": "Medium risk detected",
    "LOW": "Target looks safe",
}

SOUND_JS = """
<script>
(function () {
  var cfg = __CONFIG__;
  function playBeeps() {
    try {
      var Ctx = window.AudioContext || window.webkitAudioContext;
      var ctx = new Ctx();
      var t = ctx.currentTime;
      cfg.beeps.forEach(function (b) {
        var osc = ctx.createOscillator();
        var gain = ctx.createGain();
        osc.type = cfg.wave;
        osc.frequency.value = b[0];
        gain.gain.setValueAtTime(0.0001, t);
        gain.gain.exponentialRampToValueAtTime(0.2, t + 0.01);
        gain.gain.exponentialRampToValueAtTime(0.0001, t + b[1]);
        osc.connect(gain);
        gain.connect(ctx.destination);
        osc.start(t);
        osc.stop(t + b[1] + 0.02);
        t = t + b[1] + 0.08;
      });
    } catch (e) {}
  }
  function speak() {
    try {
      var u = new SpeechSynthesisUtterance(cfg.text);
      u.lang = "en-US";
      window.speechSynthesis.cancel();
      window.speechSynthesis.speak(u);
    } catch (e) {}
  }
  if (cfg.beep) { playBeeps(); }
  if (cfg.voice) { setTimeout(speak, cfg.delay); }
})();
</script>
"""


def run_html(code):
    """Run a small hidden HTML/JavaScript snippet (newer Streamlit: st.iframe, older: components.html)."""
    if hasattr(st, "iframe"):
        st.iframe(code, height=1)
    else:
        components.html(code, height=0)


def sound_settings():
    """Read the sidebar sound options (on/off and style)."""
    return st.session_state.get("sound_on", True), st.session_state.get("sound_style", "Both")


def sound_text(level, score):
    """Sentence read aloud for a scan result."""
    return SOUND_WORDS[level] + ". Score " + str(score)


def play_sound(level, text):
    """Play the beep pattern and/or voice for a threat level."""
    sound_on, style = sound_settings()
    if not sound_on:
        return
    pattern = SOUND_PATTERNS[level]
    beep_time = 0
    for beep in pattern["beeps"]:
        beep_time = beep_time + beep[1] + 0.08
    delay = 0
    if style == "Both":
        delay = int(beep_time * 1000) + 150      # speak after the beeps finish
    config = {
        "wave": pattern["wave"],
        "beeps": pattern["beeps"],
        "beep": style == "Beeps" or style == "Both",
        "voice": style == "Voice" or style == "Both",
        "text": text,
        "delay": delay,
        "nonce": str(datetime.now().timestamp()),    # makes every sound unique so it replays
    }
    run_html(SOUND_JS.replace("__CONFIG__", json.dumps(config)).strip())


def queue_sound(level, text):
    """Remember a sound; it is played at the end of the page (no blank gap at the top)."""
    st.session_state["pending_sound"] = {"level": level, "text": text}


def play_pending_sound():
    """Play the queued sound once, then clear it."""
    pending = st.session_state.get("pending_sound")
    if pending is not None:
        st.session_state["pending_sound"] = None
        play_sound(pending["level"], pending["text"])


def test_sound():
    """Callback of the sidebar 'Test sound' button."""
    queue_sound("CRITICAL", "Sound test. Critical threat detected.")


# ---------------------------------------------------------------
# 12. LIVE LOG FEED (simulated attacks streamed into server_logs.txt)
# ---------------------------------------------------------------
LIVE_NORMAL_IPS = ["192.168.1.10", "192.168.1.11", "192.168.1.12", "192.168.1.13", "198.51.100.9"]
LIVE_NORMAL_PATHS = ["/index.html", "/about.html", "/products", "/contact"]

# Attack scenarios that the simulator can generate
LIVE_ATTACKS = [
    {"name": "Brute force login", "ips": ["203.0.113.45", "198.51.100.77"], "path": "/login", "code": "401"},
    {"name": "Admin probing", "ips": ["203.0.113.77", "10.0.0.9"], "path": "/admin", "code": "403"},
    {"name": "SQL injection", "ips": ["192.0.2.99"], "path": "/products?id=1'+OR+1=1--", "code": "500"},
    {"name": "Malware download", "ips": ["198.51.100.23"], "path": "/download/setup.exe", "code": "200"},
    {"name": "Directory scan", "ips": ["172.16.0.8", "198.51.100.88"], "path": "/probe{n}", "code": "404"},
]

# Chance that a generated event is an attack
LIVE_INTENSITY = {"Low": 0.2, "Medium": 0.5, "High": 0.85}


def score_log_line(line):
    """Score ONE log line with the same 3-layer engine."""
    code = get_status_code(line)
    ip = get_ip(line)
    types = detect_attack_types(get_request_text(line))
    auth_fails = 0
    if code == "401" or code == "403":
        auth_fails = 1
    return score_entity(types, auth_fails, 0, feed_lookup(ip))


def build_live_event(scenario):
    """Create one log line and one table row. scenario=None means normal traffic."""
    now = datetime.now()
    if scenario is None:
        ip = random.choice(LIVE_NORMAL_IPS)
        path = random.choice(LIVE_NORMAL_PATHS)
        code = "200"
        label = "Normal traffic"
    else:
        ip = random.choice(scenario["ips"])
        path = scenario["path"].replace("{n}", str(random.randint(1000, 9999)))
        code = scenario["code"]
        label = scenario["name"]
    line = ip + ' - - [' + now.strftime("%d/%b/%Y:%H:%M:%S") + ' +0000] "GET ' + path + ' HTTP/1.1" ' + code
    result = score_log_line(line)
    event = {
        "Time": now.strftime("%H:%M:%S"),
        "Source IP": ip,
        "Event": label,
        "Request": path,
        "Status": code,
        "Risk Score": result["score"],
        "Level": result["level"],
    }
    return line, event


def generate_live_events(count, attack_chance, burst=False):
    """Create new events, append them to server_logs.txt ("a" mode) and remember them."""
    scenarios = []
    if burst:
        scenarios = list(LIVE_ATTACKS)           # one of every attack type
    else:
        for i in range(count):
            if random.random() < attack_chance:
                scenarios.append(random.choice(LIVE_ATTACKS))
            else:
                scenarios.append(None)

    lines = []
    new_events = []
    for scenario in scenarios:
        line, event = build_live_event(scenario)
        lines.append(line)
        new_events.append(event)

    file = open(LOG_FILE, "a")
    for line in lines:
        file.write(line + "\n")
    file.close()

    for event in new_events:
        if event["Risk Score"] >= 70:
            write_audit("Live alert | " + event["Source IP"] + " | " + event["Event"] + " | score "
                        + str(event["Risk Score"]) + " | " + event["Level"])

    events = st.session_state["live_events"] + new_events
    st.session_state["live_events"] = events[-100:]       # keep the latest 100
    return new_events


def highest_level(events):
    """Highest threat level found in a list of events."""
    for level in LEVEL_ORDER:
        for event in events:
            if event["Level"] == level:
                return level
    return "LOW"


def do_burst():
    """Callback: inject one of every attack type right now."""
    new_events = generate_live_events(0, 0, burst=True)
    top = highest_level(new_events)
    queue_sound(top, "Attack burst detected. " + SOUND_WORDS[top])


def clear_live():
    st.session_state["live_events"] = []


def reset_demo_logs():
    """Callback: write a fresh sample server_logs.txt and clear the live table."""
    create_sample_logs()
    st.session_state["live_events"] = []
    write_audit("Demo logs reset by analyst")


def live_tick():
    """One refresh of the live feed: 1-3 new events."""
    chance = LIVE_INTENSITY[st.session_state.get("live_intensity", "Medium")]
    new_events = generate_live_events(random.randint(1, 3), chance)
    top = highest_level(new_events)
    if top == "CRITICAL" or top == "HIGH":
        play_sound(top, "Live alert. " + SOUND_WORDS[top] + ".")


def live_feed_body():
    """This part refreshes by itself (it runs as a Streamlit fragment)."""
    if st.session_state.get("live_on", False):
        live_tick()

    events = st.session_state["live_events"]
    alerts = 0
    critical = 0
    for event in events:
        if event["Level"] == "CRITICAL" or event["Level"] == "HIGH":
            alerts = alerts + 1
        if event["Level"] == "CRITICAL":
            critical = critical + 1
    last_time = "-"
    if len(events) > 0:
        last_time = events[-1]["Time"]

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Live events", len(events))
    m2.metric("High + critical alerts", alerts)
    m3.metric("Critical", critical)
    m4.metric("Last event", last_time)

    if len(events) == 0:
        st.info("Turn on the live feed or press 'Inject attack burst' to see events here.")
        return

    left, right = st.columns([3, 1])
    with left:
        st.markdown("#### Incoming events (newest first)")
        rows = []
        for event in events[::-1][:15]:
            rows.append({
                "Time": event["Time"],
                "Source IP": event["Source IP"],
                "Event": event["Event"],
                "Request": event["Request"],
                "Status": event["Status"],
                "Risk Score": event["Risk Score"],
                "Severity": LEVEL_EMOJI[event["Level"]],
            })
        render_table(pd.DataFrame(rows), hide_index=True,
                     column_config={"Risk Score": st.column_config.ProgressColumn("Risk Score", min_value=0, max_value=100, format="%d")})
    with right:
        names = []
        values = []
        colors = []
        for level in LEVEL_ORDER:
            names.append(LEVEL_LABELS[level])
            colors.append(LEVEL_COLORS[level])
            count = 0
            for event in events:
                if event["Level"] == level:
                    count = count + 1
            values.append(count)
        fig = go.Figure(go.Bar(x=values, y=names, orientation="h", marker_color=colors, text=values, textposition="outside"))
        fig.update_layout(yaxis=dict(autorange="reversed"))
        chart_card("Severity of live events", style_fig(fig, 330), "live_severity")


def page_live():
    toggle_main = getattr(st, "toggle", st.checkbox)
    if INTEL_MODE == "real":
        st.warning("The Live Feed creates SIMULATED events and appends them to server_logs.txt. "
                   "Use 'Restore demo logs' or 'Load public sample logs' afterwards to clean the file.")

    c1, c2, c3 = st.columns([1.2, 1, 1])
    with c1:
        live_on = toggle_main("Live feed (auto-refresh)", key="live_on")
    with c2:
        st.selectbox("Attack intensity", list(LIVE_INTENSITY.keys()), index=1, key="live_intensity")
    with c3:
        seconds = st.slider("Refresh every (seconds)", 2, 10, 4, key="live_seconds")

    b1, b2, b3, b4 = st.columns(4)
    b1.button("Inject attack burst", on_click=do_burst, type="primary")
    b2.button("Clear feed", on_click=clear_live)
    b3.button("Reset demo logs", on_click=reset_demo_logs)

    if live_on:
        st.caption("Streaming: a few new events every " + str(seconds) + " seconds. They are also written to "
                   "server_logs.txt, so the other pages show the new numbers when you open them.")
    else:
        st.caption("Paused. Switch on the live feed, or inject an attack burst.")

    # st.fragment re-runs only this block every N seconds (no full page reload)
    run_every = None
    if live_on:
        run_every = seconds
    fragment = getattr(st, "fragment", None)
    if fragment is None:
        fragment = getattr(st, "experimental_fragment", None)
    if fragment is not None:
        fragment(run_every=run_every)(live_feed_body)()
    else:
        live_feed_body()                       # very old Streamlit: no auto-refresh


# ---------------------------------------------------------------
# 12b. URL FORENSICS (look-alike / obfuscation detection)
# ---------------------------------------------------------------
# Official domains of popular brands (label -> official registered domain)
BRANDS = {
    "google": "google.com", "gmail": "gmail.com", "youtube": "youtube.com", "facebook": "facebook.com",
    "instagram": "instagram.com", "whatsapp": "whatsapp.com", "twitter": "twitter.com", "linkedin": "linkedin.com",
    "microsoft": "microsoft.com", "outlook": "outlook.com", "skype": "skype.com", "apple": "apple.com",
    "icloud": "icloud.com", "amazon": "amazon.com", "paypal": "paypal.com", "netflix": "netflix.com",
    "ebay": "ebay.com", "github": "github.com", "dropbox": "dropbox.com", "adobe": "adobe.com",
    "yahoo": "yahoo.com", "telegram": "telegram.org", "snapchat": "snapchat.com", "tiktok": "tiktok.com",
    "spotify": "spotify.com", "reddit": "reddit.com", "wikipedia": "wikipedia.org", "zoom": "zoom.us",
    "slack": "slack.com", "discord": "discord.com", "binance": "binance.com", "coinbase": "coinbase.com",
    "flipkart": "flipkart.com", "paytm": "paytm.com", "phonepe": "phonepe.com", "sbi": "sbi.co.in",
    "hdfcbank": "hdfcbank.com", "icicibank": "icicibank.com", "axisbank": "axisbank.com", "irctc": "irctc.co.in",
    "wellsfargo": "wellsfargo.com", "bankofamerica": "bankofamerica.com", "chase": "chase.com", "stackoverflow": "stackoverflow.com",
}
# Other official domains that must never be flagged
EXTRA_OFFICIAL = {
    "fb.com", "youtu.be", "t.me", "microsoftonline.com", "office.com", "office365.com", "windows.com", "live.com",
    "amazonaws.com", "amazon.in", "google.co.in", "googleapis.com", "gstatic.com", "googleusercontent.com",
    "fbcdn.net", "cdninstagram.com", "wikimedia.org", "github.io", "githubusercontent.com", "x.com",
}
OFFICIAL_DOMAINS = set(BRANDS.values()).union(EXTRA_OFFICIAL)

# Country endings that brands really use (google.de is normal, google.xyz is not)
LEGIT_COUNTRY_ENDINGS = {"in", "co.in", "uk", "co.uk", "de", "fr", "jp", "co.jp", "ca", "au", "com.au", "es", "it", "nl", "br", "com.br", "mx", "sg", "com.sg", "ru"}
SECOND_LEVEL_SUFFIXES = {"co.in", "org.in", "net.in", "gov.in", "ac.in", "nic.in", "res.in", "co.uk", "org.uk", "ac.uk", "gov.uk",
                         "com.au", "net.au", "org.au", "com.br", "co.jp", "co.za", "com.cn", "com.sg", "com.pk", "co.nz",
                         "com.mx", "com.tr", "co.id", "com.my", "com.ng"}
SUSPICIOUS_TLDS = {"xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "zip", "mov", "work", "support", "loan", "icu",
                   "buzz", "country", "stream", "download", "review", "party", "gdn", "bid", "men", "trade", "science",
                   "date", "faith", "racing", "win", "vip", "rest", "monster", "cyou", "sbs"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rebrand.ly", "ow.ly", "buff.ly",
              "shorturl.at", "tiny.cc", "rb.gy", "t.ly"}
KEYWORD_WORDS = {"secure", "login", "signin", "verify", "verification", "support", "help", "account", "accounts", "update",
                 "service", "services", "official", "online", "app", "web", "mail", "pay", "payment", "payments", "bank",
                 "banking", "wallet", "security", "auth", "password", "recovery", "customer", "care", "team", "free",
                 "gift", "offer", "rewards", "claim"}
# Letters from other alphabets that look like English letters (written as \u escapes)
CONFUSABLES = {"\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c", "\u0445": "x", "\u0443": "y",
               "\u0456": "i", "\u0458": "j", "\u0455": "s", "\u0501": "d", "\u0261": "g", "\u03bf": "o", "\u03b1": "a",
               "\u03bd": "v", "\u03b9": "i", "\u03c1": "p", "\u03c4": "t", "\u03ba": "k", "\u0475": "v", "\u04bb": "h",
               "\u051b": "q", "\u051d": "w", "\u04cf": "l", "\u01c0": "l"}
LEET_SIMPLE = {"@": "a", "$": "s", "!": "i", "4": "a", "3": "e", "0": "o", "5": "s", "7": "t", "8": "b", "9": "g"}


def split_url(text):
    """Split a URL the way a browser does: user info, host, port, path."""
    rest = text.strip()
    scheme = ""
    if "://" in rest:
        scheme, rest = rest.split("://", 1)
    cut = len(rest)
    for mark in "/?#":
        position = rest.find(mark)
        if position != -1 and position < cut:
            cut = position
    authority = rest[:cut]
    path = rest[cut:]
    userinfo = ""
    host = authority
    if "@" in authority:
        userinfo, host = authority.rsplit("@", 1)      # the browser uses the LAST @
    port = ""
    if host.count(":") == 1:
        host, port = host.split(":")
    return {"scheme": scheme, "authority": authority, "userinfo": userinfo,
            "host": host.lower(), "port": port, "path": path}


def split_domain(host):
    """Return (registered domain, list of sub-domain labels)."""
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in SECOND_LEVEL_SUFFIXES:
        return ".".join(labels[-3:]), labels[:-3]
    if len(labels) >= 2:
        return ".".join(labels[-2:]), labels[:-2]
    return host, []


def ascii_skeleton(text):
    """Turn look-alike foreign letters and accents into plain a-z letters."""
    text = text.lower()
    for fake in CONFUSABLES:
        text = text.replace(fake, CONFUSABLES[fake])
    text = unicodedata.normalize("NFKD", text)
    text = "".join(ch for ch in text if unicodedata.category(ch) != "Mn")
    return text.encode("ascii", "ignore").decode("ascii")


def decode_idna(host):
    """xn--pple-43d.com -> the letters the address bar would show."""
    try:
        return host.encode("ascii").decode("idna")
    except (UnicodeError, UnicodeDecodeError):
        return host


def leet_variants(label):
    """All plain-letter readings of a label (paypa1 -> paypal, inst@gram -> instagram ...)."""
    base = label
    for symbol in LEET_SIMPLE:
        base = base.replace(symbol, LEET_SIMPLE[symbol])
    variants = set()
    for one in ["l", "i"]:
        step = base.replace("1", one)
        variants.add(step)
        variants.add(step.replace("rn", "m"))
        variants.add(step.replace("vv", "w"))
    return variants


def numeric_host_to_ip(host):
    """Detect disguised IPs such as 3232235777 or 0xC0A80001. Returns the dotted IP or ''."""
    number = -1
    try:
        if host.isdigit() and len(host) >= 8:
            number = int(host)
        elif host.startswith("0x") and "." not in host:
            number = int(host, 16)
    except ValueError:
        return ""
    if 0 <= number <= 0xFFFFFFFF:
        return ".".join([str((number >> shift) & 255) for shift in (24, 16, 8, 0)])
    return ""


def match_brand(label):
    """Compare a domain label with every brand. Returns (points, title, detail, official domain, similarity) or None."""
    best = None
    variants = leet_variants(label)
    tokens = re.split("[-_]", label)
    for brand in BRANDS:
        official = BRANDS[brand]
        candidate = None
        if label == brand:
            candidate = (35, "Same name, different domain ending",
                         "'" + label + "' is the brand name of " + official + ", but this is another domain", official, 100)
        elif brand in variants:
            candidate = (45, "Look-alike characters (leetspeak)",
                         "Digits or symbols replace letters, so '" + label + "' reads like '" + brand + "'", official, 100)
        elif len(brand) >= 4 and abs(len(label) - len(brand)) <= 2:
            ratio = SequenceMatcher(None, label, brand).ratio()
            limit = 0.82
            if len(brand) == 4:
                limit = 0.9
            if ratio >= limit:
                percent = int(ratio * 100)
                candidate = (45, "Typosquatting (spelling trick)",
                             "'" + label + "' is " + str(percent) + "% similar to '" + brand + "' (" + official + ")", official, percent)
        if candidate is None:
            for position in range(len(tokens)):
                token = tokens[position]
                if token == brand or brand in leet_variants(token):
                    for other in tokens[:position] + tokens[position + 1:]:
                        if other in KEYWORD_WORDS:
                            candidate = (35, "Brand name inside another domain",
                                         "'" + label + "' mixes '" + brand + "' with '" + other + "' to look official", official, 80)
        if candidate is None and len(brand) >= 4:
            for variant in variants.union({label}):
                if brand in variant:
                    remainder = variant.replace(brand, "", 1).strip("-_")
                    if remainder in KEYWORD_WORDS:
                        candidate = (35, "Brand name inside another domain",
                                     "'" + label + "' adds '" + remainder + "' to '" + brand + "' to look official", official, 80)
        if candidate is not None:
            if best is None or candidate[0] > best[0] or (candidate[0] == best[0] and candidate[4] > best[4]):
                best = candidate
    return best


def match_brand_in_subdomains(subs, registered):
    """Official name placed in front of a different domain (facebook.com.evil.xyz)."""
    text = ".".join(subs)
    pieces = re.split(r"[.\-_]", text)
    for brand in BRANDS:
        official = BRANDS[brand]
        if official in text:
            return (40, "Official domain used as a sub-domain",
                    "'" + official + "' is only decoration in front of the real domain '" + registered + "'", official, 100)
    for brand in BRANDS:
        if len(brand) >= 4 and brand in pieces:
            return (30, "Brand name used as a sub-domain",
                    "'" + brand + "' is only a sub-domain label of the real domain '" + registered + "'", BRANDS[brand], 80)
    return None


def add_flag(flags, title, detail, points):
    flags.append({"Technique": title, "What was found": detail, "Points": points})


def analyze_url_forensics(raw):
    """Offline check for look-alike and obfuscated URLs. Returns a dictionary with flags and points."""
    out = {"applies": False, "flags": [], "points": 0, "lookalike": "", "similarity": 0,
           "real_host": "", "clean_host": "", "official": False}
    text = raw.strip()
    if text == "" or text.startswith("/") or is_ip(text):
        return out
    if "://" not in text and "." not in text and "@" not in text:
        return out                                   # a plain word or path, not a web address
    out["applies"] = True
    flags = out["flags"]
    parts = split_url(text)
    host_raw = parts["host"]
    host = urllib.parse.unquote(host_raw)
    out["real_host"] = host_raw

    # 1. '@' trick: everything before the @ is only a user name
    if parts["userinfo"] != "":
        add_flag(flags, "'@' in the address",
                 "Text before the @ is only a user name. The browser really opens '" + host_raw
                 + "', not '" + parts["userinfo"] + "'.", 30)
        user_registered = split_domain(parts["userinfo"].lower())[0]
        if user_registered in OFFICIAL_DOMAINS:
            add_flag(flags, "Official name used as bait",
                     "'" + parts["userinfo"] + "' is a real brand domain placed before the @ to fool the reader.", 40)
            out["lookalike"] = user_registered
            out["similarity"] = 100

    # 2. Hidden or invalid characters
    if host != host_raw:
        add_flag(flags, "Percent-encoded host name", "Letters are hidden with % codes ('" + host_raw + "' becomes '" + host + "').", 25)
    bad_chars = []
    for ch in host:
        if ord(ch) < 128 and not (ch.isalnum() or ch in ".-") and ch not in bad_chars:
            bad_chars.append(ch)
    if len(bad_chars) > 0:
        add_flag(flags, "Invalid characters in the host name",
                 "Found " + " ".join(bad_chars) + " - real domain names cannot contain these, so it is an obfuscation trick.", 25)

    # 3. Punycode / foreign letters (homograph attack)
    decoded = decode_idna(host)
    has_unicode = False
    for ch in decoded:
        if ord(ch) > 127:
            has_unicode = True
    if "xn--" in host:
        add_flag(flags, "Punycode (xn--) domain", "The address bar would show: " + decoded, 25)
    elif has_unicode:
        add_flag(flags, "Non-English letters in the domain", "The domain uses letters from another alphabet: " + decoded, 30)
    skeleton = ascii_skeleton(decoded)
    homograph = has_unicode and skeleton != decoded
    clean = "".join(ch for ch in skeleton if ch.isalnum() or ch in ".-")
    out["clean_host"] = clean

    # 4. Disguised IP addresses
    hidden_ip = numeric_host_to_ip(host)
    if hidden_ip != "":
        add_flag(flags, "Disguised IP address", "'" + host + "' is really the IP address " + hidden_ip + ".", 30)
    elif is_ip(host):
        add_flag(flags, "IP address instead of a domain", "Legitimate sites almost never ask you to log in on a bare IP address.", 25)

    # 5. Compare with famous brands
    if hidden_ip == "" and not is_ip(host):
        candidates = [("host", clean)]
        if parts["userinfo"] != "":
            visual = urllib.parse.unquote(parts["authority"].lower()).replace("@", "a")
            candidates.append(("visual", ascii_skeleton(visual)))
        real_registered = split_domain(clean[4:] if clean.startswith("www.") else clean)[0]
        best = None
        for kind, domain_text in candidates:
            domain_text = domain_text.strip(".")
            if domain_text.startswith("www."):
                domain_text = domain_text[4:]
            registered, subs = split_domain(domain_text)
            found = None
            if registered in OFFICIAL_DOMAINS:
                if kind == "visual" and registered != real_registered:
                    found = (45, "Fake official look ('@' replaces a letter)",
                             "Read with '@' as 'a' the address looks like " + registered + ", but it really goes to " + real_registered,
                             registered, 100)
                elif kind == "host" and homograph:
                    found = (50, "Homograph attack (look-alike foreign letters)",
                             "The domain looks like " + registered + " but uses letters from another alphabet", registered, 100)
                elif kind == "host" and (len(bad_chars) > 0 or host != host_raw):
                    found = (45, "Obfuscated copy of an official domain",
                             "After removing the hidden characters this is " + registered, registered, 100)
            elif kind == "visual":
                continue                                  # the "@ = a" reading only matters for official look-alikes
            else:
                label = registered.split(".")[0]
                found = match_brand(label)
                if found is not None and found[1] == "Same name, different domain ending":
                    ending = registered[len(label) + 1:]
                    if ending in LEGIT_COUNTRY_ENDINGS:
                        found = None
                if found is None and len(subs) > 0:
                    found = match_brand_in_subdomains(subs, registered)
            if found is not None and (best is None or found[0] > best[0]):
                best = found
        if best is not None:
            add_flag(flags, best[1], best[2], best[0])
            out["lookalike"] = best[3]
            out["similarity"] = best[4]

        # 6. Other warning signs (only for domains that are not official)
        registered, subs = split_domain(clean[4:] if clean.startswith("www.") else clean)
        if registered in OFFICIAL_DOMAINS and len(flags) == 0:
            out["official"] = True
        elif registered not in OFFICIAL_DOMAINS:
            if registered.split(".")[-1] in SUSPICIOUS_TLDS:
                add_flag(flags, "Risky domain ending", "." + registered.split(".")[-1] + " is cheap and often abused for phishing.", 15)
            if registered in SHORTENERS:
                add_flag(flags, "Link shortener", "The real destination is hidden behind " + registered + ".", 10)
            if len(subs) >= 3:
                add_flag(flags, "Many sub-domains", str(len(subs)) + " sub-domain levels hide the real domain.", 10)
            if clean.count("-") >= 4:
                add_flag(flags, "Many hyphens", "Long hyphenated names are typical of throw-away phishing domains.", 10)
            if len(text) > 100:
                add_flag(flags, "Very long address", str(len(text)) + " characters - long URLs hide the real host.", 10)

    total = 0
    for flag in flags:
        total = total + flag["Points"]
    out["points"] = min(total, URL_CAP)
    return out


def forensics_advice(forensics):
    """Plain-language response for a suspicious URL."""
    steps = ["Do not click the link and never type a password on it."]
    if forensics["lookalike"] != "":
        steps.append("The official website is probably " + forensics["lookalike"] + " - type that address yourself.")
    steps.append("The browser would really connect to: " + forensics["real_host"] + ".")
    steps.append("Block the domain in the DNS filter or web proxy, and warn users who received the link.")
    steps.append("Report it: Google Safe Browsing (safebrowsing.google.com/safebrowsing/report_phish) or the brand's abuse page.")
    return steps


def show_forensics_panel(result):
    """Panel with the look-alike analysis of the typed URL."""
    forensics = result["forensics"]
    if not forensics["applies"]:
        return
    st.markdown("#### URL Forensics (look-alike and obfuscation check)")
    if forensics["official"]:
        st.markdown('<div class="lookalike-box safe"><div><div class="cap">Verdict</div>'
                    '<div class="dom real">Official domain - no tricks found</div></div></div>', unsafe_allow_html=True)
        return
    if len(forensics["flags"]) == 0:
        st.success("No look-alike or obfuscation tricks found in this address.")
        return
    shown = forensics["real_host"]
    if shown == "":
        shown = result["host"]
    box = ('<div class="lookalike-box"><div><div class="cap">Typed address</div>'
           '<div class="dom fake">' + html.escape(result["target"]) + '</div></div>')
    if forensics["lookalike"] != "":
        box = box + ('<div class="arrow">&#8594;</div><div><div class="cap">Pretends to be (' + str(forensics["similarity"]) + '% match)</div>'
                     '<div class="dom real">' + html.escape(forensics["lookalike"]) + '</div></div>')
    box = box + ('<div class="arrow">&#8594;</div><div><div class="cap">Browser really opens</div>'
                 '<div class="dom">' + html.escape(shown) + '</div></div></div>')
    st.markdown(box, unsafe_allow_html=True)
    render_table(pd.DataFrame(forensics["flags"]), hide_index=True)
    st.markdown("**Recommended response**")
    for step in forensics_advice(forensics):
        st.markdown("- " + step)


# ---------------------------------------------------------------
# 12c. OSINT INVESTIGATION (passive - the suspicious site is never opened)
# ---------------------------------------------------------------
def doh_query(name, record_type):
    """DNS lookup through Cloudflare DNS-over-HTTPS. Returns (answer dict, error text)."""
    url = "https://cloudflare-dns.com/dns-query?" + urllib.parse.urlencode({"name": name, "type": record_type})
    data, error = api_get_json(url, {"Accept": "application/dns-json"})
    if data is None:
        return None, error
    answers = []
    for item in data.get("Answer", []):
        answers.append(str(item.get("data", "")).strip('"'))
    return {"status": data.get("Status", 0), "answers": answers}, ""


def parse_rdap_domain(data):
    """Pick the useful fields out of an RDAP (WHOIS) answer."""
    info = {"registered": "", "changed": "", "expires": "", "age_days": None,
            "registrar": "-", "status": [], "nameservers": []}
    for event in data.get("events", []):
        action = event.get("eventAction", "")
        date = str(event.get("eventDate", ""))[:10]
        if action == "registration":
            info["registered"] = date
        elif action == "last changed":
            info["changed"] = date
        elif action == "expiration":
            info["expires"] = date
    if info["registered"] != "":
        try:
            born = datetime.strptime(info["registered"], "%Y-%m-%d")
            info["age_days"] = (datetime.now() - born).days
        except ValueError:
            pass
    for entity in data.get("entities", []):
        if "registrar" in entity.get("roles", []):
            try:
                for item in entity["vcardArray"][1]:
                    if item[0] == "fn":
                        info["registrar"] = str(item[3])
            except (KeyError, IndexError, TypeError):
                pass
    info["status"] = data.get("status", [])
    for server in data.get("nameservers", []):
        info["nameservers"].append(str(server.get("ldhName", "")).lower())
    return info


def crtsh_lookup(domain):
    """Certificate Transparency logs (crt.sh): which certificates and sub-domains exist."""
    url = "https://crt.sh/?q=" + urllib.parse.quote("%." + domain) + "&output=json"
    data, error = api_get_json(url, {"Accept": "application/json"})
    if data is None:
        return None, error
    names = []
    first_seen = ""
    for entry in data[:300]:
        for name in str(entry.get("name_value", "")).split("\n"):
            name = name.strip().lower().lstrip("*.")
            if name != "" and name not in names:
                names.append(name)
        date = str(entry.get("not_before", ""))[:10]
        if date != "" and (first_seen == "" or date < first_seen):
            first_seen = date
    return {"certificates": len(data), "names": names[:40], "first_seen": first_seen}, ""


def osint_investigate(target):
    """Collect public information about a domain or IP. Needs internet. Never contacts the target itself."""
    host = get_host(target)
    report = {"host": host, "registered_domain": "", "valid_host": True, "errors": [], "dns": [],
              "rdap": None, "ip_rdap": None, "ct": None, "ips": [], "ip_info": [], "findings": [], "points": 0}
    findings = report["findings"]

    if is_ip(host):
        report["ips"] = [host]
        data, error = api_get_json("https://rdap.org/ip/" + host, {"Accept": "application/rdap+json"})
        if data is None:
            report["errors"].append("IP registry (RDAP): " + error)
        else:
            report["ip_rdap"] = {"name": data.get("name", "-"), "country": data.get("country", "-"),
                                 "range": str(data.get("startAddress", "-")) + " - " + str(data.get("endAddress", "-")),
                                 "handle": data.get("handle", "-")}
    else:
        valid = re.fullmatch(r"[a-z0-9.\-]+", host) is not None and "." in host
        if not valid:
            report["valid_host"] = False
            findings.append({"Finding": "Invalid host name",
                             "Detail": "This name cannot be resolved normally - it only exists to confuse readers.", "Points": 0})
        else:
            registered, subs = split_domain(host)
            report["registered_domain"] = registered
            for record_type in ["A", "MX", "NS", "TXT"]:
                name = host
                if record_type == "MX" or record_type == "NS":
                    name = registered
                answer, error = doh_query(name, record_type)
                if answer is None:
                    report["errors"].append("DNS " + record_type + ": " + error)
                    continue
                for value in answer["answers"]:
                    report["dns"].append({"Type": record_type, "Value": value[:120]})
                    if record_type == "A":
                        report["ips"].append(value)
                if record_type == "A" and answer["status"] == 3:
                    findings.append({"Finding": "Domain does not exist (NXDOMAIN)",
                                     "Detail": "Typo domains are often unregistered or already taken down.", "Points": 0})
            data, error = api_get_json("https://rdap.org/domain/" + registered, {"Accept": "application/rdap+json"})
            if data is None:
                report["errors"].append("WHOIS / RDAP: " + error)
            else:
                report["rdap"] = parse_rdap_domain(data)
                age = report["rdap"]["age_days"]
                if age is not None and age < 30:
                    findings.append({"Finding": "Very new domain", "Detail": "Registered only " + str(age) + " days ago.", "Points": 30})
                elif age is not None and age < 180:
                    findings.append({"Finding": "Young domain", "Detail": "Registered " + str(age) + " days ago.", "Points": 15})
                elif age is not None:
                    findings.append({"Finding": "Established domain", "Detail": "Registered " + str(age // 365) + " years ago.", "Points": 0})
            ct, error = crtsh_lookup(registered)
            if ct is None:
                report["errors"].append("Certificate logs (crt.sh): " + error)
            else:
                report["ct"] = ct
                if ct["first_seen"] != "":
                    try:
                        age = (datetime.now() - datetime.strptime(ct["first_seen"], "%Y-%m-%d")).days
                        if age < 14:
                            findings.append({"Finding": "First certificate is brand new",
                                             "Detail": "The first HTTPS certificate was issued " + str(age) + " days ago.", "Points": 10})
                    except ValueError:
                        pass

    # Where do the resolved IPs live, and are they known to be bad?
    ips = report["ips"][:5]
    if len(ips) > 0:
        public_ips = [ip for ip in ips if is_ip(ip) and not is_private_ip(ip)]
        if len(public_ips) > 0:
            geolocate_ips(public_ips)
        for ip in ips:
            geo = GEO_CACHE.get(ip, {})
            feed = feed_lookup(ip)
            listed = "No"
            if feed is not None:
                listed = feed["category"]
                if not is_ip(host):                      # for a bare IP the feed is already part of the score
                    findings.append({"Finding": "Resolves to a known bad IP", "Detail": ip + " - " + feed["category"], "Points": 30})
            report["ip_info"].append({"IP": ip, "Country": geo.get("country", "-"), "ISP": geo.get("isp", "-"), "Listed in feeds": listed})

    total = 0
    for finding in findings:
        total = total + finding["Points"]
    report["points"] = min(total, 60)
    return report


def show_osint_panel(result):
    """Expander with the OSINT investigation."""
    saved = st.session_state.get("osint_result")
    opened = saved is not None and saved["target"] == result["target"]
    with st.expander("OSINT investigation: DNS, WHOIS, certificates (passive, needs internet)", expanded=opened):
        show_osint_body(result)


def show_osint_body(result):
    """Button + results of the OSINT investigation."""
    st.caption("Uses public DNS-over-HTTPS (Cloudflare), WHOIS/RDAP (rdap.org) and certificate logs (crt.sh). "
               "The suspicious site itself is never opened or contacted.")
    target = result["target"]
    if st.button("Run OSINT investigation"):
        with st.spinner("Collecting public information..."):
            report = osint_investigate(target)
        st.session_state["osint_result"] = {"target": target, "report": report}
        write_audit("OSINT investigation | " + target + " | osint points " + str(report["points"]))
    saved = st.session_state.get("osint_result")
    if saved is None or saved["target"] != target:
        return
    report = saved["report"]

    rdap = report["rdap"]
    age_text = "-"
    registrar = "-"
    if rdap is not None:
        registrar = rdap["registrar"]
        if rdap["age_days"] is not None:
            age_text = str(rdap["age_days"]) + " days"
    certs = "-"
    if report["ct"] is not None:
        certs = report["ct"]["certificates"]
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Domain age", age_text)
    m2.metric("Registrar", registrar)
    m3.metric("Resolved IPs", len(report["ips"]))
    m4.metric("Certificates seen", certs)

    left, right = st.columns(2)
    with left:
        if len(report["dns"]) > 0:
            st.markdown("**DNS records**")
            render_table(pd.DataFrame(report["dns"]), hide_index=True)
        if report["ip_rdap"] is not None:
            st.markdown("**IP registry (RDAP)**")
            render_table(pd.DataFrame([report["ip_rdap"]]), hide_index=True)
    with right:
        if len(report["ip_info"]) > 0:
            st.markdown("**Where the IPs live**")
            render_table(pd.DataFrame(report["ip_info"]), hide_index=True)
        if report["ct"] is not None and len(report["ct"]["names"]) > 0:
            st.markdown("**Names seen in certificate logs**")
            render_table(pd.DataFrame({"Host name": report["ct"]["names"]}), hide_index=True)

    if len(report["findings"]) > 0:
        st.markdown("**OSINT findings**")
        render_table(pd.DataFrame(report["findings"]), hide_index=True)
    for error in report["errors"]:
        st.caption("Could not read: " + error)

    combined = min(100, result["score"] + report["points"])
    level = get_level(combined)
    st.markdown('<div class="lookalike-box ' + ("safe" if level == "LOW" else "") + '"><div><div class="cap">Combined risk after OSINT</div>'
                '<div class="dom">' + str(result["score"]) + ' + ' + str(report["points"]) + ' = ' + str(combined) + ' / 100 &nbsp; '
                + badge_html(level) + '</div></div></div>', unsafe_allow_html=True)
    st.caption("OSINT results are clues, not proof. A new domain is not always malicious, and an old one can be hacked.")


def build_investigation_report(result):
    """Everything known about the scanned target as one dictionary (JSON download)."""
    saved = st.session_state.get("osint_result")
    osint = None
    if saved is not None and saved["target"] == result["target"]:
        osint = saved["report"]
    return {
        "report": "ThreatVision Pro - Investigation Report",
        "generated_at": str(datetime.now()),
        "target": result["target"],
        "score": result["score"],
        "level": result["level"],
        "layers": result["layers"],
        "vectors": result["vectors"],
        "url_forensics": result["forensics"],
        "threat_feed": result["feed"],
        "osint": osint,
    }


def executive_summary_html(summary):
    """A few plain sentences that summarise the whole dashboard."""
    counts = summary["counts"]
    total_ips = len(summary["ips"])
    items = []
    flagged = counts["CRITICAL"] + counts["HIGH"] + counts["MEDIUM"]
    items.append("<b>" + str(flagged) + "</b> of " + str(total_ips) + " IP addresses need attention ("
                 + str(counts["CRITICAL"]) + " critical, " + str(counts["HIGH"]) + " high, " + str(counts["MEDIUM"]) + " medium).")

    top_ip = ""
    top_score = -1
    vector_counts = {}
    for ip in summary["ips"]:
        result = summary["ips"][ip]["result"]
        if result["score"] > top_score:
            top_score = result["score"]
            top_ip = ip
        for vector in result["vectors"]:
            vector_counts[vector["Vector"]] = vector_counts.get(vector["Vector"], 0) + 1
    if top_score >= 40:
        items.append("Highest risk: <b>" + html.escape(top_ip) + "</b> with score <b>" + str(top_score) + "</b> ("
                     + html.escape(get_category(summary["ips"][top_ip]["result"])) + ").")
    top_vector = ""
    top_count = 0
    for name in vector_counts:
        if vector_counts[name] > top_count:
            top_count = vector_counts[name]
            top_vector = name
    if top_vector != "":
        items.append("Most common attack technique: <b>" + html.escape(top_vector) + "</b> (" + str(top_count) + " IPs).")

    failed = 0
    for code in ["401", "403", "404"]:
        failed = failed + summary["status_counts"].get(code, 0)
    if summary["total_logs"] > 0:
        items.append("<b>" + str(round(failed * 100 / summary["total_logs"])) + "%</b> of all requests failed (401, 403 or 404).")
    peak_hour = ""
    peak = 0
    for hour in summary["hourly_all"]:
        if summary["hourly_all"][hour] > peak:
            peak = summary["hourly_all"][hour]
            peak_hour = hour
    if peak_hour != "":
        items.append("Busiest hour: <b>" + peak_hour + ":00</b> with " + str(peak) + " requests.")

    text = ""
    for item in items:
        text = text + "<li>" + item + "</li>"
    return '<div class="card exec-card"><div class="exec-title">Executive summary</div><ul>' + text + '</ul></div>'


# ---------------------------------------------------------------
# 12e. LOGIN, SESSION AND PROFILE PHOTO
# ---------------------------------------------------------------
DISPLAY_NAME = "Devbrat Kurchaniya"
ROLE_TEXT = "Security Analyst · SOC"
AUTH_USER = "devbrat_kurchaniya"
# The password is NOT stored in this file. Only a salted PBKDF2 hash is kept.
# To change it run:  python threat_analyzer.py --hash "your new password"
AUTH_SALT = "f052f0d5d6ce82e25dd1e0b1d5946274"
AUTH_HASH = "1863fd35a78d81213e0930a7e4240e54bd6162c2540219e1bec2705533edba82"
AUTH_ITERATIONS = 200000
MAX_FAILS = 5              # wrong attempts before the form is locked
LOCK_SECONDS = 60          # how long it stays locked
IDLE_MINUTES = 30          # automatic sign-out after this much inactivity
PHOTO_FILES = ["profile_photo.png", "profile_photo.jpg", "profile.png", "profile.jpg", "profile.jpeg"]


def hash_password(password, salt_hex, iterations=AUTH_ITERATIONS):
    """Salted PBKDF2-HMAC-SHA256 hash of a password (hex text)."""
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), iterations).hex()


def check_login(username, password):
    """True only when BOTH user name and password are right (constant-time comparison)."""
    user_ok = hmac.compare_digest(username.strip().encode("utf-8"), AUTH_USER.encode("utf-8"))
    pass_ok = hmac.compare_digest(hash_password(password, AUTH_SALT), AUTH_HASH)
    return user_ok and pass_ok


def do_logout():
    """Callback of the Sign out button."""
    write_audit("Logout | " + AUTH_USER)
    st.session_state["auth"] = False
    st.session_state["login_notice"] = "You have been signed out."


def check_idle():
    """Sign the user out after IDLE_MINUTES without any action."""
    now = time.time()
    last = st.session_state.get("last_active", now)
    if now - last > IDLE_MINUTES * 60:
        write_audit("Auto sign-out (idle) | " + AUTH_USER)
        st.session_state["auth"] = False
        st.session_state["login_notice"] = "Session expired after " + str(IDLE_MINUTES) + " minutes of inactivity."
        st.rerun()
    st.session_state["last_active"] = now


def initials():
    """DK for Devbrat Kurchaniya."""
    letters = ""
    for word in DISPLAY_NAME.split():
        letters = letters + word[0].upper()
    return letters[:2]


def load_photo_uri():
    """Profile photo as a data URI (small square picture), or '' when there is none."""
    for name in PHOTO_FILES:
        if os.path.exists(name):
            try:
                from PIL import Image
                image = Image.open(name).convert("RGB")
                side = min(image.size)
                left = (image.size[0] - side) // 2
                top = (image.size[1] - side) // 2
                image = image.crop((left, top, left + side, top + side)).resize((240, 240))
                import io
                buffer = io.BytesIO()
                image.save(buffer, format="PNG")
                return "data:image/png;base64," + base64.b64encode(buffer.getvalue()).decode("ascii")
            except Exception:
                return ""
    return ""


def avatar_html():
    """Round profile picture, or the initials when no photo exists."""
    uri = st.session_state.get("photo_uri", "")
    if uri != "":
        return '<img class="avatar" src="' + uri + '" alt="profile">'
    return '<div class="avatar">' + html.escape(initials()) + '</div>'


def save_profile_photo(uploaded):
    """Save an uploaded picture as profile_photo.png and show it everywhere."""
    from PIL import Image
    image = Image.open(uploaded).convert("RGB")
    side = min(image.size)
    left = (image.size[0] - side) // 2
    top = (image.size[1] - side) // 2
    image = image.crop((left, top, left + side, top + side)).resize((240, 240))
    image.save("profile_photo.png")
    st.session_state["photo_uri"] = load_photo_uri()


def login_page():
    """Full-screen sign-in page. Nothing else is shown until the login succeeds."""
    theme = st.session_state.get("theme_choice", DEFAULT_THEME)
    if theme not in THEMES:
        theme = DEFAULT_THEME
    apply_theme(theme)
    hide_sidebar = ("<style>[data-testid='stSidebar'], [data-testid='stSidebarCollapsedControl'], "
                    "[data-testid='stSidebarCollapseButton'] { display: none; }</style>")
    st.markdown(build_css(theme, False) + hide_sidebar, unsafe_allow_html=True)
    if "photo_uri" not in st.session_state:
        st.session_state["photo_uri"] = load_photo_uri()

    _, middle, _ = st.columns([1, 1.15, 1])
    with middle:
        st.write("")
        st.write("")
        with card_container("login"):
            st.markdown('<div class="login-logo">TV</div><div class="login-title">ThreatVision Pro</div>'
                        '<div class="login-sub">Sign in to your security operations workspace</div>', unsafe_allow_html=True)
            notice = st.session_state.pop("login_notice", "")
            if notice != "":
                st.info(notice)
            remaining = int(st.session_state.get("locked_until", 0) - time.time())
            with st.form("login_form"):
                username = st.text_input("Username", key="login_user")
                password = st.text_input("Password", type="password", key="login_pass")
                submitted = st.form_submit_button("Sign in", type="primary", disabled=remaining > 0)
            if remaining > 0:
                st.warning("Too many wrong attempts. Try again in " + str(remaining) + " seconds.")
            if submitted:
                if check_login(username, password):
                    st.session_state["auth"] = True
                    st.session_state["fail_count"] = 0
                    st.session_state["last_active"] = time.time()
                    write_audit("Login success | " + AUTH_USER)
                    st.rerun()
                else:
                    st.session_state["fail_count"] = st.session_state.get("fail_count", 0) + 1
                    write_audit("Login failed | user typed: " + username.strip()[:30])
                    left = MAX_FAILS - st.session_state["fail_count"]
                    if left <= 0:
                        st.session_state["locked_until"] = time.time() + LOCK_SECONDS
                        st.session_state["fail_count"] = 0
                        st.error("Too many wrong attempts. The form is locked for " + str(LOCK_SECONDS) + " seconds.")
                    else:
                        st.error("Wrong username or password. " + str(left) + " attempt(s) left.")
            st.markdown('<div class="login-foot">Authorised use only · every sign-in is logged</div>', unsafe_allow_html=True)


# ---------------------------------------------------------------
# 13. REAL-WORLD INTELLIGENCE (open feeds, real logs, optional VirusTotal / AbuseIPDB)
# ---------------------------------------------------------------
def feed_path(feed):
    """Where a downloaded feed is stored."""
    return os.path.join(INTEL_DIR, feed["id"] + ".txt")


def read_utf8_file(path):
    """Read a text file as UTF-8 ("r" mode). Returns "" when it does not exist."""
    text = ""
    try:
        file = open(path, "r", encoding="utf-8", errors="replace")
        text = file.read()
        file.close()
    except FileNotFoundError:
        pass
    return text


def download_text(url, max_bytes=40 * 1024 * 1024):
    """Download a text file from the internet (standard library only)."""
    request = urllib.request.Request(url, headers={"User-Agent": "ThreatVision/2.0 (student project)"})
    with urllib.request.urlopen(request, timeout=30) as response:
        data = response.read(max_bytes)
    return data.decode("utf-8", errors="replace")


def update_feeds():
    """Download every open feed into intel_cache/ ("w" mode). Returns (downloaded, messages)."""
    os.makedirs(INTEL_DIR, exist_ok=True)
    downloaded = 0
    messages = []
    network_errors = 0
    for feed in FEEDS:
        if network_errors >= 2:
            messages.append(feed["name"] + ": skipped (no internet?)")
            continue
        try:
            text = download_text(feed["url"])
            file = open(feed_path(feed), "w", encoding="utf-8")
            file.write(text)
            file.close()
            downloaded = downloaded + 1
            network_errors = 0
        except urllib.error.HTTPError as error:
            messages.append(feed["name"] + ": server answered HTTP " + str(error.code))
        except Exception:
            network_errors = network_errors + 1
            messages.append(feed["name"] + ": could not be downloaded")
    return downloaded, messages


def feeds_need_update():
    """True when the main feed is missing or older than FEED_MAX_AGE_HOURS."""
    path = feed_path(FEEDS[0])
    if not os.path.exists(path):
        return True
    age_hours = (datetime.now().timestamp() - os.path.getmtime(path)) / 3600
    return age_hours > FEED_MAX_AGE_HOURS


def feed_stamp():
    """Changes whenever a feed file changes (used as a cache key)."""
    parts = []
    for feed in FEEDS:
        path = feed_path(feed)
        if os.path.exists(path):
            parts.append(str(os.path.getmtime(path)))
    return "|".join(parts)


def normalize_url(url):
    """Lower-case URL without http://, www. and the trailing slash."""
    url = url.strip().lower()
    if "://" in url:
        url = url.split("://", 1)[1]
    if url.startswith("www."):
        url = url[4:]
    return url.rstrip("/")


def ipsum_points(count):
    """IPsum counts on how many blocklists an IP appears. More lists = more trust."""
    if count >= 5:
        return 40
    elif count == 4:
        return 38
    elif count == 3:
        return 30
    elif count == 2:
        return 20
    return 10


def add_ip_hit(ips, ip, hit):
    """Store one feed hit (source, points, category, attack type) for an IP."""
    if ip in ips:
        ips[ip].append(hit)
    else:
        ips[ip] = [hit]


def parse_feeds():
    """Read the downloaded feed files into dictionaries (fast lookups)."""
    data = {"ips": {}, "domains": {}, "urls": {}, "status": [],
            "examples": {"c2": [], "top": [], "domains": [], "urls": []}}
    for feed in FEEDS:
        path = feed_path(feed)
        text = read_utf8_file(path)
        entries = 0
        hit = None
        if feed["kind"] == "domains" or feed["kind"] == "urls":
            hit = (feed["short"], feed["points"], feed["category"], feed["attack"])   # shared by all entries
        for raw in text.split("\n"):
            line = raw.strip()
            if line == "" or line.startswith("#"):
                continue
            if feed["kind"] == "ipsum":
                parts = line.split()
                if is_ip(parts[0]):
                    count = 1
                    if len(parts) > 1 and parts[1].isdigit():
                        count = int(parts[1])
                    add_ip_hit(data["ips"], parts[0], ("IPsum", ipsum_points(count),
                               "Known attacker (on " + str(count) + " blocklists)", None))
                    entries = entries + 1
                    if count >= 5 and len(data["examples"]["top"]) < 500:
                        data["examples"]["top"].append(parts[0])
            elif feed["kind"] == "iplist":
                if is_ip(line):
                    add_ip_hit(data["ips"], line, (feed["short"], feed["points"], feed["category"], feed["attack"]))
                    entries = entries + 1
                    if feed["attack"] == "Botnet C2":
                        data["examples"]["c2"].append(line)
            elif feed["kind"] == "domains":
                data["domains"][line.lower()] = hit
                entries = entries + 1
                if len(data["examples"]["domains"]) < 2000:
                    data["examples"]["domains"].append(line.lower())
            elif feed["kind"] == "urls":
                normal = normalize_url(line)
                data["urls"][normal] = hit
                entries = entries + 1
                if len(data["examples"]["urls"]) < 2000:
                    data["examples"]["urls"].append(line)
                host = get_host(normal)
                if is_ip(host):                      # many malware URLs use a bare IP address
                    add_ip_hit(data["ips"], host, (feed["short"], 35, "Malware host IP (" + feed["short"] + ")", None))
        updated = "-"
        if os.path.exists(path):
            updated = datetime.fromtimestamp(os.path.getmtime(path)).strftime("%Y-%m-%d %H:%M")
        status = "Loaded"
        if entries == 0:
            status = "No data"
        data["status"].append({"Feed": feed["name"], "Type": feed["type_label"],
                               "Entries": entries, "Updated": updated, "Status": status})
    return data


@st.cache_resource(show_spinner="Loading threat feeds into memory...")
def load_intel_cached(stamp):
    """Parse the feeds once and keep the result in memory (until a feed file changes)."""
    return parse_feeds()


def prepare_real_intel():
    """Real mode: download feeds when missing or old (once per session), then load them."""
    messages = []
    if not st.session_state.get("feeds_checked", False):
        st.session_state["feeds_checked"] = True
        if feeds_need_update():
            with st.spinner("Downloading open threat feeds (the first time this is about 15 MB)..."):
                downloaded, notes = update_feeds()
            messages = messages + notes
            write_audit("Threat feeds updated | " + str(downloaded) + " of " + str(len(FEEDS)) + " downloaded")
    return load_intel_cached(feed_stamp()), messages


def real_feed_lookup(target):
    """Look an IP, domain or URL up in the open feeds. Returns a feed dict or None."""
    if not INTEL_DATA:
        return None
    host = get_host(target)
    hits = []
    if is_ip(host):
        hits = INTEL_DATA["ips"].get(host, [])
    else:
        normal = normalize_url(target)
        if normal in INTEL_DATA["urls"]:
            hits.append(INTEL_DATA["urls"][normal])
        parts = host.split(".")
        for i in range(len(parts) - 1):                  # also check the parent domains
            candidate = ".".join(parts[i:])
            if candidate in INTEL_DATA["domains"]:
                hits.append(INTEL_DATA["domains"][candidate])
                break
    if len(hits) == 0:
        return None

    best = hits[0]
    for hit in hits:
        if hit[1] > best[1]:
            best = hit
    points = best[1] + 5 * (len(hits) - 1)               # +5 for every extra feed
    if points > 40:
        points = 40
    attack = None
    for hit in hits:
        if hit[3] is not None:
            attack = hit[3]
            break
    if attack is not None:
        points = points + FEED_CONFIRM_BONUS             # a feed confirmed the attack type
    sources = []
    for hit in hits:
        if hit[0] not in sources:
            sources.append(hit[0])
    geo = GEO_CACHE.get(host, {})
    return {
        "abuse": points * 100 // REPUTATION_CAP,
        "vt": len(hits),
        "country": geo.get("country", "Not looked up"),
        "lat": geo.get("lat"),
        "lon": geo.get("lon"),
        "category": best[2],
        "points": points,
        "attack_type": attack,
        "sources": sources,
        "real": True,
    }


def pick_real_example(kind):
    """Pick a random REAL malicious indicator from the loaded feeds."""
    pool = []
    if INTEL_DATA:
        if kind == "c2":
            pool = INTEL_DATA["examples"]["c2"]
        elif kind == "ip":
            pool = INTEL_DATA["examples"]["top"]
        elif kind == "domain":
            pool = INTEL_DATA["examples"]["domains"]
        elif kind == "url":
            pool = INTEL_DATA["examples"]["urls"]
    if len(pool) == 0:
        return ""
    return random.choice(pool)


def run_real_example(kind):
    """Callback of the 'Real ...' buttons: fill the box and scan."""
    target = pick_real_example(kind)
    if target == "":
        st.session_state["notice"] = "No data for this example yet. Press 'Update threat feeds' in the sidebar (needs internet)."
        return
    st.session_state["target_box"] = target
    st.session_state["sim_auth"] = 0
    st.session_state["sim_ports"] = 0
    st.session_state["preset_used"] = True
    st.session_state["scan_now"] = True


# ---- real geolocation (ip-api.com, free, up to 100 IPs per request) ----
def load_geo_cache():
    text = read_utf8_file(GEO_FILE)
    if text == "":
        return {}
    try:
        return json.loads(text)
    except ValueError:
        return {}


def save_geo_cache():
    os.makedirs(INTEL_DIR, exist_ok=True)
    file = open(GEO_FILE, "w", encoding="utf-8")
    file.write(json.dumps(GEO_CACHE))
    file.close()


def geolocate_ips(ips):
    """Look up real countries for a list of IPs. Returns (added, message)."""
    added = 0
    try:
        for start in range(0, len(ips), 100):
            chunk = ips[start:start + 100]
            request = urllib.request.Request(
                "http://ip-api.com/batch?fields=status,country,lat,lon,isp,query",
                data=json.dumps(chunk).encode("utf-8"),
                headers={"Content-Type": "application/json", "User-Agent": "ThreatVision/2.0"})
            with urllib.request.urlopen(request, timeout=20) as response:
                results = json.loads(response.read().decode("utf-8"))
            for item in results:
                if item.get("status") == "success":
                    GEO_CACHE[item["query"]] = {"country": item.get("country", "Unknown"),
                                                "lat": item.get("lat"), "lon": item.get("lon"),
                                                "isp": item.get("isp", "")}
                    added = added + 1
    except Exception:
        save_geo_cache()
        return added, "Geolocation stopped early (no internet or the free limit was reached)."
    save_geo_cache()
    return added, ""


def flagged_public_ips(summary, limit=300):
    """Public IPs worth locating: score 40+ or listed in a feed, not located yet."""
    ips = []
    for ip in summary["ips"]:
        result = summary["ips"][ip]["result"]
        if is_ip(ip) and not is_private_ip(ip) and ip not in GEO_CACHE:
            if result["score"] >= 40 or result["feed"] is not None:
                ips.append(ip)
    return ips[:limit]


def show_real_intel_panel(summary):
    """Threat Intel page extras for real mode: feed status + real geolocation."""
    geo_note = st.session_state.get("geo_note", "")
    if geo_note != "":
        st.warning(geo_note)
        st.session_state["geo_note"] = ""
    st.markdown("#### Open Feed Status")
    if not INTEL_DATA:
        st.warning("No feed data loaded. Press 'Update threat feeds' in the sidebar (needs internet).")
    else:
        render_table(pd.DataFrame(INTEL_DATA["status"]), hide_index=True)
    pending = flagged_public_ips(summary)
    c1, c2 = st.columns([1, 3])
    clicked = c1.button("Locate flagged IPs", disabled=len(pending) == 0)
    c2.caption(str(len(pending)) + " flagged public IPs are not located yet. Uses the free ip-api.com service "
               "(only those IPs are sent, not your logs).")
    if clicked:
        with st.spinner("Looking up locations..."):
            added, message = geolocate_ips(pending)
        write_audit("Geolocation | " + str(added) + " IPs located")
        st.session_state["geo_note"] = message
        st.rerun()


# ---- optional live lookups with the analyst's own API keys ----
def api_get_json(url, headers):
    """GET a URL and return (json, error_text)."""
    headers["User-Agent"] = "ThreatVision/2.0"
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return json.loads(response.read().decode("utf-8")), ""
    except urllib.error.HTTPError as error:
        messages = {401: "Invalid API key", 403: "Access denied", 404: "Not found in this database",
                    429: "Rate limit reached - wait a minute and try again"}
        return None, messages.get(error.code, "HTTP error " + str(error.code))
    except Exception:
        return None, "Network error - check your internet connection"


def get_api_key(state_key, env_name):
    """Key typed in the sidebar, or from an environment variable."""
    key = st.session_state.get(state_key, "").strip()
    if key == "":
        key = os.environ.get(env_name, "")
    return key


def vt_lookup(target, key):
    """VirusTotal v3 lookup of an IP, domain or URL."""
    host = get_host(target)
    if is_ip(target):
        path = "ip_addresses/" + target
        link = "https://www.virustotal.com/gui/ip-address/" + target
    elif "/" in target or "?" in target:
        full_url = target
        if "://" not in full_url:
            full_url = "http://" + full_url
        url_id = base64.urlsafe_b64encode(full_url.encode("utf-8")).decode("ascii").strip("=")
        path = "urls/" + url_id
        link = "https://www.virustotal.com/gui/url/" + url_id
    else:
        path = "domains/" + host
        link = "https://www.virustotal.com/gui/domain/" + host
    data, error = api_get_json("https://www.virustotal.com/api/v3/" + path, {"x-apikey": key})
    if data is None:
        if error == "Not found in this database":
            error = "VirusTotal has not scanned this exact target yet."
        return {"error": error}
    attributes = data.get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})
    return {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "reputation": attributes.get("reputation", 0),
        "country": attributes.get("country", "-"),
        "owner": attributes.get("as_owner", "-"),
        "link": link,
    }


def abuse_lookup(ip, key):
    """AbuseIPDB v2 check of one IP."""
    url = "https://api.abuseipdb.com/api/v2/check?" + urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": 90})
    data, error = api_get_json(url, {"Key": key, "Accept": "application/json"})
    if data is None:
        return {"error": error}
    info = data.get("data", {})
    return {
        "score": info.get("abuseConfidenceScore", 0),
        "reports": info.get("totalReports", 0),
        "country": info.get("countryCode", "-"),
        "isp": info.get("isp", "-"),
        "usage": info.get("usageType", "-"),
        "last": info.get("lastReportedAt", "-"),
    }


def show_live_lookups(result):
    """Expander with the VirusTotal / AbuseIPDB buttons."""
    opened = st.session_state.get("vt_result") is not None or st.session_state.get("abuse_result") is not None
    with st.expander("Live lookups: VirusTotal and AbuseIPDB (your own API key)", expanded=opened):
        show_live_lookups_body(result)


def show_live_lookups_body(result):
    """Buttons for VirusTotal / AbuseIPDB (they use the analyst's own free API keys)."""
    target = result["target"]
    vt_key = get_api_key("vt_key", "VT_API_KEY")
    abuse_key = get_api_key("abuse_key", "ABUSEIPDB_API_KEY")
    c1, c2 = st.columns(2)
    with c1:
        if vt_key == "":
            st.caption("Add a free VirusTotal API key in the sidebar (API keys) to enable this.")
        elif st.button("Check on VirusTotal"):
            st.session_state["vt_result"] = {"target": target, "data": vt_lookup(target, vt_key)}
            write_audit("VirusTotal lookup | " + target)
    with c2:
        if abuse_key == "":
            st.caption("Add a free AbuseIPDB API key in the sidebar (API keys) to enable this.")
        elif not is_ip(result["host"]):
            st.caption("AbuseIPDB works for IP addresses only.")
        elif st.button("Check on AbuseIPDB"):
            st.session_state["abuse_result"] = {"target": target, "data": abuse_lookup(target, abuse_key)}
            write_audit("AbuseIPDB lookup | " + target)

    vt_saved = st.session_state.get("vt_result")
    if vt_saved is not None and vt_saved["target"] == target:
        data = vt_saved["data"]
        if "error" in data:
            st.warning("VirusTotal: " + data["error"])
        else:
            v1, v2, v3, v4 = st.columns(4)
            v1.metric("VT malicious", data["malicious"])
            v2.metric("VT suspicious", data["suspicious"])
            v3.metric("VT harmless", data["harmless"])
            v4.metric("VT undetected", data["undetected"])
            st.caption("Reputation " + str(data["reputation"]) + " · Country " + str(data["country"])
                       + " · Owner " + str(data["owner"]) + " · [Open on VirusTotal](" + data["link"] + ")")
    abuse_saved = st.session_state.get("abuse_result")
    if abuse_saved is not None and abuse_saved["target"] == target:
        data = abuse_saved["data"]
        if "error" in data:
            st.warning("AbuseIPDB: " + data["error"])
        else:
            a1, a2, a3 = st.columns(3)
            a1.metric("AbuseIPDB confidence", str(data["score"]) + "%")
            a2.metric("Total reports", data["reports"])
            a3.metric("Country", data["country"])
            st.caption("ISP " + str(data["isp"]) + " · Usage " + str(data["usage"]) + " · Last reported " + str(data["last"]))


# ---- real log files ----
def save_logs_text(text):
    """Replace server_logs.txt with new log text ("w" mode). The old file is saved once as a backup."""
    if os.path.exists(LOG_FILE) and os.path.getsize(LOG_FILE) > 0 and not os.path.exists(LOG_BACKUP):
        shutil.copyfile(LOG_FILE, LOG_BACKUP)
    lines = []
    for line in text.split("\n"):
        line = line.strip()
        if line != "":
            lines.append(line)
        if len(lines) >= REAL_LOG_LIMIT:
            break
    file = open(LOG_FILE, "w", encoding="utf-8")
    file.write("\n".join(lines) + "\n")
    file.close()
    return len(lines)


def format_log_line(ip, path, code, moment):
    """One log line in the usual web-server format."""
    return (ip + ' - - [' + moment.strftime("%d/%b/%Y:%H:%M:%S") + ' +0000] "GET ' + path
            + ' HTTP/1.1" ' + code)


def build_real_intel_test_logs():
    """Write a TEST log: simulated traffic coming from REAL malicious IPs taken from the loaded feeds.
    The IP addresses and their reputation are real; the requests are simulated."""
    if not INTEL_DATA or len(INTEL_DATA["ips"]) == 0:
        return 0
    bad_ips = []
    for ip in INTEL_DATA["examples"]["c2"][:5]:
        bad_ips.append(ip)
    top = INTEL_DATA["examples"]["top"]
    for ip in random.sample(top, min(25, len(top))):
        if ip not in bad_ips:
            bad_ips.append(ip)
    all_ips = list(INTEL_DATA["ips"].keys())
    for ip in random.sample(all_ips, min(30, len(all_ips))):
        if ip not in bad_ips:
            bad_ips.append(ip)

    now = datetime.now()
    lines = []
    for i in range(300):                                  # normal visitors
        moment = now - timedelta(minutes=random.randint(0, 1400))
        lines.append(format_log_line(random.choice(LIVE_NORMAL_IPS), random.choice(LIVE_NORMAL_PATHS), "200", moment))
    for ip in bad_ips:                                    # attackers
        scenario = random.choice(LIVE_ATTACKS)
        for k in range(random.randint(3, 12)):
            moment = now - timedelta(minutes=random.randint(0, 1400))
            path = scenario["path"].replace("{n}", str(random.randint(1000, 9999)))
            lines.append(format_log_line(ip, path, scenario["code"], moment))
    random.shuffle(lines)
    return save_logs_text("\n".join(lines))


def queue_task(name):
    """Callback: remember which sidebar task to run (it runs with a spinner in the main section)."""
    st.session_state["task"] = name


def run_tasks(after_intel=False):
    """Run the task chosen with a sidebar button. Returns a list of messages.
    Tasks that need the loaded feeds run in a second call (after_intel=True)."""
    task = st.session_state.get("task")
    notes = []
    if after_intel:
        if task == "feed_test_logs":
            st.session_state["task"] = None
            count = build_real_intel_test_logs()
            if count == 0:
                notes.append("No feed data loaded yet. Press 'Update threat feeds' first (needs internet).")
            else:
                write_audit("Built test logs from real malicious IPs | " + str(count) + " lines")
                notes.append("Built " + str(count) + " test log lines: simulated requests from REAL malicious IPs.")
        return notes
    if task == "feed_test_logs":
        return notes                                      # runs later, once the feeds are loaded
    st.session_state["task"] = None
    if task == "update_feeds":
        with st.spinner("Downloading open threat feeds..."):
            downloaded, messages = update_feeds()
        st.session_state["feeds_checked"] = True
        write_audit("Threat feeds updated | " + str(downloaded) + " of " + str(len(FEEDS)) + " downloaded")
        notes.append("Feeds updated: " + str(downloaded) + " of " + str(len(FEEDS)) + " downloaded.")
        notes = notes + messages
    elif task == "load_real_logs":
        try:
            with st.spinner("Downloading a real public web-server log..."):
                count = save_logs_text(download_text(REAL_SAMPLE_LOG_URL))
            write_audit("Loaded public sample logs | " + str(count) + " lines")
            notes.append("Loaded " + str(count) + " real log lines (public Nginx sample from 2015).")
        except Exception:
            notes.append("Could not download the sample logs (check your internet).")
    elif task == "demo_logs":
        create_sample_logs()
        st.session_state["live_events"] = []
        write_audit("Demo logs restored by analyst")
        notes.append("Demo logs restored.")
    return notes


def handle_upload(uploaded):
    """Use an uploaded log file as server_logs.txt. Returns a message."""
    if uploaded is None:
        st.session_state["last_upload"] = ""
        return ""
    key = uploaded.name + ":" + str(uploaded.size)
    if st.session_state.get("last_upload", "") == key:
        return ""
    st.session_state["last_upload"] = key
    count = save_logs_text(uploaded.getvalue().decode("utf-8", errors="replace"))
    write_audit("Uploaded log file | " + uploaded.name + " | " + str(count) + " lines")
    return "Loaded " + str(count) + " lines from " + uploaded.name


# ---------------------------------------------------------------
# 14. MAIN APP
# ---------------------------------------------------------------
ensure_streamlit_config()      # creates .streamlit/config.toml once (restart the app after the first run)
st.set_page_config(page_title="ThreatVision Pro", page_icon="🛡️", layout="wide")
setup_state()

# --- Security: nothing below runs until the user has signed in ---
if not st.session_state["auth"]:
    login_page()
    st.stop()
check_idle()
if "photo_uri" not in st.session_state:
    st.session_state["photo_uri"] = load_photo_uri()

# --- Sidebar: widgets first (uploads and tasks must run BEFORE the logs are read) ---
brand_box = st.sidebar.container()          # profile card (filled later, when the numbers are ready)
with brand_box:
    profile_slot = st.empty()
    with st.expander("Profile photo"):
        photo_file = st.file_uploader("Upload a picture (PNG or JPG)", type=["png", "jpg", "jpeg"], key="photo_upload")
        if photo_file is not None and st.session_state.get("photo_name", "") != photo_file.name + str(photo_file.size):
            try:
                save_profile_photo(photo_file)
                st.session_state["photo_name"] = photo_file.name + str(photo_file.size)
                write_audit("Profile photo changed | " + AUTH_USER)
            except Exception:
                st.warning("This file could not be used as a picture.")
    try:
        st.button("Sign out", on_click=do_logout, icon=":material/logout:", key="signout_button")
    except TypeError:
        st.button("Sign out", on_click=do_logout, key="signout_button")

st.sidebar.markdown(side_label_html("Navigation"), unsafe_allow_html=True)
for index in range(len(PAGES)):
    prefix = "navoff_"
    if PAGES[index] == st.session_state["page"]:
        prefix = "navon_"                                 # the CSS highlights the open page
    try:
        st.sidebar.button(PAGES[index], key=prefix + str(index), on_click=go_page, args=(PAGES[index],),
                          icon=PAGE_ICONS[PAGES[index]])
    except TypeError:                                     # older Streamlit: no icon support
        st.sidebar.button(PAGES[index], key=prefix + str(index), on_click=go_page, args=(PAGES[index],))
page = st.session_state["page"]

st.sidebar.markdown(side_label_html("Filters"), unsafe_allow_html=True)
severity_choice = st.sidebar.selectbox("Threat severity filter", list(SEVERITY_FILTERS.keys()),
                                       label_visibility="collapsed")
min_score = SEVERITY_FILTERS[severity_choice]

st.sidebar.markdown(side_label_html("Appearance"), unsafe_allow_html=True)
theme_name = st.sidebar.selectbox("Colour theme", list(THEMES.keys()), key="theme_choice", label_visibility="collapsed")
toggle_widget = getattr(st.sidebar, "toggle", st.sidebar.checkbox)    # toggle switch on new Streamlit
present_mode = toggle_widget("Presentation mode")

st.sidebar.markdown(side_label_html("Alerts"), unsafe_allow_html=True)
toggle_widget("Sound alerts", value=True, key="sound_on")
st.sidebar.selectbox("Sound style", SOUND_STYLES, index=2, key="sound_style", label_visibility="collapsed")
st.sidebar.button("Test sound", on_click=test_sound)

st.sidebar.markdown(side_label_html("Data & Intelligence"), unsafe_allow_html=True)
intel_choice = st.sidebar.selectbox("Intelligence mode", INTEL_MODES, key="intel_mode", label_visibility="collapsed")
if intel_choice == INTEL_MODES[1]:
    st.sidebar.button("Update threat feeds", on_click=queue_task, args=("update_feeds",))
    st.sidebar.button("Load public sample logs", on_click=queue_task, args=("load_real_logs",))
    st.sidebar.button("Build test logs from real bad IPs", on_click=queue_task, args=("feed_test_logs",))
st.sidebar.button("Restore demo logs", on_click=queue_task, args=("demo_logs",))
uploaded_log = st.sidebar.file_uploader("Upload your own log file", type=["log", "txt"], key="log_upload")
with st.sidebar.expander("API keys (optional)"):
    st.text_input("VirusTotal API key", type="password", key="vt_key")
    st.text_input("AbuseIPDB API key", type="password", key="abuse_key")
    st.caption("Free keys: virustotal.com and abuseipdb.com. Keys stay in this browser session only. "
               "You can also set the VT_API_KEY and ABUSEIPDB_API_KEY environment variables.")

# --- Run sidebar tasks and uploads, then prepare the intelligence mode ---
notes = run_tasks()
upload_note = handle_upload(uploaded_log)
if upload_note != "":
    notes.append(upload_note)

INTEL_MODE = "demo"
INTEL_DATA = {}
GEO_CACHE = {}
if intel_choice == INTEL_MODES[1]:
    INTEL_MODE = "real"
    INTEL_DATA, feed_notes = prepare_real_intel()
    notes = notes + feed_notes
    GEO_CACHE = load_geo_cache()
    notes = notes + run_tasks(after_intel=True)

# --- First-run automation: create sample logs if server_logs.txt is missing or empty ---
if (not os.path.exists(LOG_FILE)) or os.path.getsize(LOG_FILE) == 0:
    create_sample_logs()
    write_audit("Auto-created sample server_logs.txt (first run)")

# --- Load and analyse the logs (cached: only re-runs when the file or the feeds change) ---
logs = read_logs()
log_stamp = (os.path.getmtime(LOG_FILE), os.path.getsize(LOG_FILE))
intel_stamp = INTEL_MODE
if INTEL_MODE == "real":
    intel_stamp = INTEL_MODE + ":" + feed_stamp()
summary = cached_summary(log_stamp, intel_stamp)
profile_slot.markdown(sidebar_profile_html(summary), unsafe_allow_html=True)

st.sidebar.markdown(side_label_html("System"), unsafe_allow_html=True)
for note in notes:
    st.sidebar.info(note)
if INTEL_MODE == "real" and not INTEL_DATA:
    st.sidebar.warning("No feed data yet. Press 'Update threat feeds' (needs internet).")
if len(logs) == 0:
    st.sidebar.warning("server_logs.txt not found or empty.")
    st.sidebar.button("Create sample server_logs.txt", on_click=create_sample_logs)
else:
    st.sidebar.button("Re-scan logs", on_click=rescan_logs)
    write_report(summary)                          # overwrite threat_report.txt ("w")
    if "audit_done" not in st.session_state:       # one audit line per session ("a")
        write_audit("Log analysis | logs: " + str(len(logs)) + " | critical: " + str(summary["counts"]["CRITICAL"])
                    + " | high: " + str(summary["counts"]["HIGH"]) + " | medium: " + str(summary["counts"]["MEDIUM"]))
        st.session_state["audit_done"] = True
st.sidebar.markdown(sidebar_stats_html(summary), unsafe_allow_html=True)

# --- Apply the theme: charts (globals) + CSS ---
apply_theme(theme_name)
st.markdown(build_css(theme_name, present_mode), unsafe_allow_html=True)

# --- Page header + metric cards ---
st.markdown(page_header_html(page, len(logs)), unsafe_allow_html=True)
if page != "Overview":
    st.markdown(kpi_strip_html(summary), unsafe_allow_html=True)

# --- Show the selected page ---
if page == "Overview":
    page_overview(summary, min_score)
elif page == "Live Scanner":
    page_scanner(logs)
elif page == "Live Feed":
    page_live()
elif page == "Threat Intel & Map":
    page_geo(summary, min_score)
elif page == "MITRE ATT&CK":
    page_mitre(summary)
else:
    page_reports(summary, logs)

# --- Play a queued alert sound (kept at the very end so it leaves no gap) ---
play_pending_sound()
