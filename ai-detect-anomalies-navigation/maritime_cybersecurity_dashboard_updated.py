"""
Maritime Cybersecurity Dashboard + Simple Blockchain (Single File)

Features:
- Loads or generates samples for: login_logs.csv, ais_positions.csv, malicious_ip_list.csv
- Optional auto-extract of uploaded zip (if present at /mnt/data/64a1ab64-8537-4b69-b32c-3e0fc00e7c92.zip)
- Detects consecutive failed logins per Ship_ID+Username
- Suspicious IP detection (sliding window)
- IP geolocation caching, AIS join, blocklist management
- Email alerts (Gmail App Password) — test button included (disabled by default)
- Download threat report as Excel (xlsx) with CSV fallback
- Simple on-disk blockchain ledger: each alert is stored as a block (timestamp, data, prev_hash, hash)
- Blockchain display and integrity verification in UI
- Clean watchdog observer shutdown

Usage:
    streamlit run maritime_dashboard_with_blockchain.py

Notes:
- Replace EMAIL_SENDER and EMAIL_PASSWORD with your Gmail and App Password to enable email sending.
- The app will attempt to extract an uploaded zip if present at the path used during your session:
  /mnt/data/64a1ab64-8537-4b69-b32c-3e0fc00e7c92.zip
"""

import os
import json
import time
import random
import socket
import hashlib
import warnings
import smtplib
import ipaddress
import threading
import requests
import zipfile
import pandas as pd
import folium
import plotly.express as px

from io import BytesIO
from datetime import datetime, timezone, timedelta
from email.mime.text import MIMEText
from streamlit_folium import folium_static
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import streamlit as st

warnings.simplefilter(action="ignore", category=FutureWarning)

# ---------------- CONFIG ----------------
LOG_FILE = "login_logs.csv"
AIS_FILE = "ais_positions.csv"
MAL_IP_FILE = "malicious_ip_list.csv"

SUSPICIOUS_FILE = "suspicious_logs.csv"
LEDGER_FILE = "evidence_ledger.json"
ALERT_HISTORY_FILE = "alert_history.csv"
BLOCKLIST_FILE = "ip_blocklist.json"
GEO_CACHE_FILE = "ip_geo_cache.json"
BLOCKCHAIN_FILE = "blockchain_ledger.json"
FILES_TO_MONITOR = ["config.txt", "system.log"]

# Email credentials (local testing only). Replace before enabling email.
EMAIL_SENDER = "yourgmail@gmail.com"
EMAIL_PASSWORD = "abcdefghijklmnop"  # 16-char App Password (no spaces)
EMAIL_RECEIVER = "security_officer@gmail.com"
ENABLE_EMAIL_ALERTS = False  # Change to True only after configuring EMAIL_* correctly

# Path to uploaded zip (user provided). The system will try to extract it if present.
UPLOADED_ZIP_PATH = "/mnt/data/64a1ab64-8537-4b69-b32c-3e0fc00e7c92.zip"

# ---------------- SIMPLE BLOCKCHAIN ----------------
class SimpleBlockchain:
    def __init__(self, path=BLOCKCHAIN_FILE):
        self.path = path
        self.chain = []
        self._load()

    def _load(self):
        if os.path.exists(self.path):
            try:
                with open(self.path, "r") as f:
                    self.chain = json.load(f)
            except Exception:
                self.chain = []
        else:
            # Genesis block
            genesis = self._create_block({"type": "genesis", "note": "blockchain created"}, prev_hash="0")
            self.chain = [genesis]
            self._save()

    def _save(self):
        try:
            with open(self.path, "w") as f:
                json.dump(self.chain, f, indent=2)
        except Exception:
            pass

    def _hash_block(self, block):
        block_str = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_str).hexdigest()

    def _create_block(self, data, prev_hash):
        timestamp = datetime.now(timezone.utc).isoformat()
        block = {"index": len(self.chain) + 1 if self.chain else 1,
                 "timestamp": timestamp,
                 "data": data,
                 "prev_hash": prev_hash}
        block_hash = self._hash_block(block)
        block["hash"] = block_hash
        return block

    def add_block(self, data):
        prev_hash = self.chain[-1]["hash"] if self.chain else "0"
        block = self._create_block(data, prev_hash)
        self.chain.append(block)
        self._save()
        return block

    def verify_chain(self):
        errs = []
        for i in range(1, len(self.chain)):
            prev = self.chain[i-1]
            curr = self.chain[i]
            # Check linkage
            if curr.get("prev_hash") != prev.get("hash"):
                errs.append(f"Link mismatch at index {i+1}")
            # Recompute hash
            recomputed = self._hash_block({k: curr[k] for k in curr if k != "hash"})
            if recomputed != curr.get("hash"):
                errs.append(f"Tampered block at index {i+1}")
        return errs

# instantiate blockchain
blockchain = SimpleBlockchain()

# ---------------- HELPERS ----------------
def to_excel_bytes(df):
    output = BytesIO()
    for engine in ("xlsxwriter", "openpyxl"):
        try:
            with pd.ExcelWriter(output, engine=engine) as writer:
                df.to_excel(writer, index=False, sheet_name="Report")
            return output.getvalue()
        except Exception:
            output.seek(0); output.truncate(0)
            continue
    return df.to_csv(index=False).encode("utf-8")

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(str(ip))
        return True
    except Exception:
        return False

def generate_random_ip():
    return f"192.168.{random.randint(0,5)}.{random.randint(1,254)}"

def file_hash(filename):
    try:
        with open(filename, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception:
        return None

def update_ledger(file, ledger_file):
    timestamp = datetime.now(timezone.utc).isoformat()
    filehash = file_hash(file)
    ledger = {}
    if os.path.exists(ledger_file):
        try:
            with open(ledger_file, "r") as f:
                ledger = json.load(f)
        except Exception:
            ledger = {}
    ledger[file] = {"hash": filehash, "timestamp": timestamp}
    try:
        with open(ledger_file, "w") as f:
            json.dump(ledger, f, indent=2)
    except Exception:
        pass
    return ledger

def send_email_alert(subject, message, receiver=None, force_send=False, sender=None, password=None):
    receiver = receiver or EMAIL_RECEIVER
    sender = (sender or EMAIL_SENDER).strip()
    # Gmail App Passwords are 16 chars; Google often shows them with spaces – strip spaces
    password = (password or EMAIL_PASSWORD or "").replace(" ", "").strip()
    if not (ENABLE_EMAIL_ALERTS or force_send):
        st.info("Email alerts disabled. Enable ENABLE_EMAIL_ALERTS or use Test Email with credentials to send.")
        return
    try:
        msg = MIMEText(message)
        msg["Subject"] = subject
        msg["From"] = sender
        msg["To"] = receiver
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(sender, password)
            server.sendmail(sender, receiver, msg.as_string())
    except smtplib.SMTPAuthenticationError as e:
        st.warning(
            "⚠️ Gmail rejected your login. Use an **App Password**, not your normal password. "
            "Turn on 2-Step Verification, then create one at: Google Account → Security → App passwords. "
            "Paste the 16-character password (spaces are removed automatically)."
        )
        raise
    except Exception as e:
        st.warning(f"⚠️ Email sending failed: {e}")
        raise

def log_alert(alert_msg):
    timestamp = datetime.now().isoformat()
    entry = pd.DataFrame([{"Timestamp": timestamp, "Alert": alert_msg}])
    if os.path.exists(ALERT_HISTORY_FILE):
        entry.to_csv(ALERT_HISTORY_FILE, mode="a", index=False, header=False)
    else:
        entry.to_csv(ALERT_HISTORY_FILE, index=False)

def send_alert(message, email=True, record_blockchain=True):
    # UI + log + optional email + add to blockchain
    st.error(f"🚨 ALERT: {message}")
    log_alert(message)
    if email:
        send_email_alert("Maritime Cybersecurity Alert", message)
    if record_blockchain:
        # add compact block data
        block_data = {"alert": message}
        blockchain.add_block(block_data)

# ---------------- WATCHDOG ----------------
class LogHandler(FileSystemEventHandler):
    def on_modified(self, event):
        try:
            if os.path.basename(event.src_path) == os.path.basename(LOG_FILE):
                st.experimental_rerun()
        except Exception:
            pass

observer = Observer()
try:
    observer.schedule(LogHandler(), path=".", recursive=False)
    threading.Thread(target=observer.start, daemon=True).start()
except Exception:
    pass

# ---------------- OPTIONAL: EXTRACT UPLOADED ZIP ----------------
def try_extract_uploaded_zip(zip_path=UPLOADED_ZIP_PATH):
    if os.path.exists(zip_path):
        try:
            with zipfile.ZipFile(zip_path, "r") as z:
                z.extractall(".")
            return True, f"Extracted {zip_path}"
        except Exception as e:
            return False, f"Failed to extract {zip_path}: {e}"
    return False, "No uploaded zip present"

extracted, extract_msg = try_extract_uploaded_zip()
if extracted:
    st.info(extract_msg)

# ---------------- SAMPLE DATA GENERATORS ----------------
def generate_sample_login(path, rows=400):
    start = datetime.now() - timedelta(days=3)
    ships = [101, 102, 103, 104, 105]
    users = ["alice", "bob", "charlie", "david", "eve", "manas", "admin"]
    statuses = ["Success", "Fail"]
    data = []
    suspicious_ips = ["192.168.1.10", "192.168.2.20", "192.168.3.30"]
    for ip in suspicious_ips:
        ship = random.choice(ships)
        user = random.choice(users)
        t0 = start + timedelta(hours=random.randint(0,48))
        for k in range(6):
            data.append({
                "Ship_ID": ship,
                "Username": user,
                "Login_Status": "Fail",
                "Timestamp": (t0 + timedelta(seconds=k*20)).strftime("%Y-%m-%d %H:%M:%S"),
                "IP": ip
            })
    for i in range(rows - len(data)):
        ts = start + timedelta(minutes=random.randint(0, 60*48))
        ip = random.choice(suspicious_ips + [generate_random_ip() for _ in range(20)])
        row = {
            "Ship_ID": random.choice(ships),
            "Username": random.choice(users),
            "Login_Status": random.choices(statuses, weights=[0.78, 0.22])[0],
            "Timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "IP": ip
        }
        data.append(row)
    df = pd.DataFrame(data)
    df.to_csv(path, index=False)
    return df

def generate_sample_ais(path, rows=250):
    start = datetime.now() - timedelta(days=3)
    ships = [101, 102, 103, 104, 105]
    data = []
    for _ in range(rows):
        ship = random.choice(ships)
        lat = 10 + random.random() * 20
        lon = 70 + random.random() * 20
        ts = start + timedelta(minutes=random.randint(0, 60*48))
        data.append({"Ship_ID": ship, "Latitude": round(lat, 5), "Longitude": round(lon, 5), "Timestamp": ts.strftime("%Y-%m-%d %H:%M:%S")})
    df = pd.DataFrame(data)
    df.to_csv(path, index=False)
    return df

def generate_sample_malicious(path):
    ips = [f"203.0.113.{i}" for i in range(1, 101)]
    df = pd.DataFrame({"IP": ips})
    df.to_csv(path, index=False)
    return df

# ---------------- LOAD OR GENERATE CSVs ----------------
if not os.path.exists(LOG_FILE):
    st.warning(f"{LOG_FILE} not found — generating a realistic sample for demo.")
    login_df = generate_sample_login(LOG_FILE)
else:
    login_df = pd.read_csv(LOG_FILE)

if not os.path.exists(AIS_FILE):
    st.info(f"{AIS_FILE} not found — generating sample AIS positions.")
    ais_df = generate_sample_ais(AIS_FILE)
else:
    ais_df = pd.read_csv(AIS_FILE)

if not os.path.exists(MAL_IP_FILE):
    st.info(f"{MAL_IP_FILE} not found — generating sample malicious IP list.")
    mal_df = generate_sample_malicious(MAL_IP_FILE)
else:
    mal_df = pd.read_csv(MAL_IP_FILE)

# Normalize timestamps
if "Timestamp" in login_df.columns:
    login_df["Timestamp"] = pd.to_datetime(login_df["Timestamp"], errors="coerce")
else:
    login_df["Timestamp"] = pd.to_datetime(datetime.now())

if "Timestamp" in ais_df.columns:
    ais_df["Timestamp"] = pd.to_datetime(ais_df["Timestamp"], errors="coerce")

# Ensure IP column
if "IP" not in login_df.columns:
    login_df["IP"] = [generate_random_ip() for _ in range(len(login_df))]
login_df["IP_Valid"] = login_df["IP"].apply(lambda x: is_valid_ip(x) if pd.notna(x) else False)

try:
    malicious_set = set(mal_df["IP"].astype(str).tolist())
except Exception:
    malicious_set = set()

# ---------------- CONSECUTIVE FAIL DETECTION ----------------
for c in ["Ship_ID", "Username", "Login_Status"]:
    if c not in login_df.columns:
        login_df[c] = None

login_df["Fail_Flag"] = (login_df["Login_Status"] == "Fail").astype(int)
login_df["_zero_blocks"] = login_df.groupby(["Ship_ID", "Username"])["Fail_Flag"].transform(lambda x: (x == 0).cumsum())
login_df["Consec_Fails"] = login_df.groupby(["Ship_ID", "Username", "_zero_blocks"])["Fail_Flag"].cumsum()
login_df.drop(columns=["_zero_blocks"], inplace=True)

suspicious = login_df[login_df.get("Consec_Fails", 0) >= 3]
if not suspicious.empty:
    suspicious.to_csv(SUSPICIOUS_FILE, index=False)
    update_ledger(SUSPICIOUS_FILE, LEDGER_FILE)

# Update ledger for critical files
for f in FILES_TO_MONITOR:
    if os.path.exists(f):
        update_ledger(f, LEDGER_FILE)

# ---------------- SUSPICIOUS IP DETECTION ----------------
def detect_suspicious_ips(df, max_fails=5, max_unique_users=4, time_window_minutes=10):
    df_valid = df[df["IP_Valid"]].copy()
    if df_valid.empty:
        return pd.DataFrame(), pd.DataFrame()
    fails_by_ip = df_valid[df_valid["Login_Status"] == "Fail"].groupby("IP").size().rename("Fail_Count").reset_index()
    users_by_ip = df_valid.groupby("IP")["Username"].nunique().rename("Unique_Users").reset_index()
    ships_by_ip = df_valid.groupby("IP")["Ship_ID"].nunique().rename("Unique_Ships").reset_index()
    ip_summary = fails_by_ip.merge(users_by_ip, on="IP", how="outer").merge(ships_by_ip, on="IP", how="outer").fillna(0)
    ip_summary[["Fail_Count", "Unique_Users", "Unique_Ships"]] = ip_summary[["Fail_Count", "Unique_Users", "Unique_Ships"]].astype(int)
    ip_summary["Flag"] = (ip_summary["Fail_Count"] >= max_fails) | (ip_summary["Unique_Users"] >= max_unique_users)
    flagged = ip_summary[ip_summary["Flag"]].copy()
    # sliding-window
    df_valid_sorted = df_valid.sort_values("Timestamp").reset_index(drop=True)
    time_window_seconds = time_window_minutes * 60
    for ip in df_valid_sorted["IP"].unique():
        ip_fails = df_valid_sorted[(df_valid_sorted["IP"] == ip) & (df_valid_sorted["Login_Status"] == "Fail")].sort_values("Timestamp")
        if ip_fails.shape[0] < 2:
            continue
        times = ip_fails["Timestamp"].astype("int64") // 1_000_000_000
        times = times.reset_index(drop=True)
        i = 0
        for j in range(len(times)):
            while (times[j] - times[i]) > time_window_seconds:
                i += 1
            if (j - i + 1) >= max_fails:
                flagged = pd.concat([flagged, pd.DataFrame([{
                    "IP": ip,
                    "Fail_Count": (j - i + 1),
                    "Unique_Users": ip_fails["Username"].nunique(),
                    "Unique_Ships": ip_fails["Ship_ID"].nunique(),
                    "Flag": True
                }])], ignore_index=True)
                break
    flagged = flagged.drop_duplicates(subset=["IP"])
    return ip_summary, flagged

ip_summary, flagged_ips = detect_suspicious_ips(login_df, max_fails=5, max_unique_users=4, time_window_minutes=10)

# send alerts for flagged ips and suspicious logins (also record to blockchain)
if not flagged_ips.empty:
    for _, r in flagged_ips.iterrows():
        send_alert(f"Suspicious IP {r['IP']} — fails: {int(r['Fail_Count'])}, users: {int(r['Unique_Users'])}", email=False, record_blockchain=True)

if not suspicious.empty:
    for _, row in suspicious.iterrows():
        send_alert(f"User {row['Username']} on Ship {row['Ship_ID']} had {row['Consec_Fails']} consecutive failed logins!", email=False, record_blockchain=True)

# ---------------- AIS JOIN ----------------
def attach_nearest_ais(login_df, ais_df, window_minutes=10):
    if ais_df.empty:
        login_df["AIS_Lat"] = None; login_df["AIS_Lon"] = None; login_df["AIS_Time"] = None
        return login_df
    ais_by_ship = {sid: group.sort_values("Timestamp").reset_index(drop=True) for sid, group in ais_df.groupby("Ship_ID")}
    ais_lat=[]; ais_lon=[]; ais_time=[]
    delta = timedelta(minutes=window_minutes)
    for _, row in login_df.iterrows():
        sid = row.get("Ship_ID"); ts = row.get("Timestamp")
        lat = lon = atime = None
        if pd.isna(ts) or sid not in ais_by_ship:
            ais_lat.append(lat); ais_lon.append(lon); ais_time.append(atime); continue
        candidates = ais_by_ship[sid]
        diffs = (candidates["Timestamp"] - ts).abs()
        min_idx = diffs.idxmin()
        if diffs.loc[min_idx] <= pd.Timedelta(delta):
            lat = candidates.loc[min_idx, "Latitude"]
            lon = candidates.loc[min_idx, "Longitude"]
            atime = candidates.loc[min_idx, "Timestamp"]
        ais_lat.append(lat); ais_lon.append(lon); ais_time.append(atime)
    login_df = login_df.copy()
    login_df["AIS_Lat"]=ais_lat; login_df["AIS_Lon"]=ais_lon; login_df["AIS_Time"]=ais_time
    return login_df

merged_df = attach_nearest_ais(login_df, ais_df, window_minutes=10)
merged_df["Is_Malicious_IP"] = merged_df["IP"].astype(str).apply(lambda x: x in malicious_set)

# ---------------- STREAMLIT UI ----------------
st.set_page_config(page_title="Maritime Cybersecurity Dashboard + Blockchain", layout="wide")

# Background: Unsplash beach/ocean image
BACKGROUND_URL = "https://images.unsplash.com/photo-1507525428034-b723cf961d3e"
st.markdown(
    f"""
    <style>
    .stApp {{
        background-image: url("{BACKGROUND_URL}");
        background-size: cover;
        background-attachment: fixed;
    }}
    .stApp::before {{
        content: "";
        position: fixed;
        top: 0; left: 0; right: 0; bottom: 0;
        background: rgba(0,0,0,0.45);
        pointer-events: none;
        z-index: 0;
    }}
    [data-testid="stAppViewContainer"] {{ background: transparent; }}
    </style>
    """,
    unsafe_allow_html=True,
)

# Project home URL (backend serves frontend on port 5000)
HOME_PAGE_URL = "https://forensic-investigation-framework-marine-p5l7.onrender.com/home.html"

# Sidebar: Go back (link to project home) + Utilities
st.sidebar.markdown(
    f'<p style="margin-bottom:0.5rem;"><a href="{HOME_PAGE_URL}" target="_self" style="color:#4fc3f7;text-decoration:none;font-weight:600;">← Go back to Home</a></p>'
    '<p style="font-size:0.85rem;color:#888;">Opens project home page.</p>',
    unsafe_allow_html=True,
)
st.sidebar.markdown("---")
st.sidebar.markdown("### Utilities & Settings")
st.sidebar.caption("**You (worker)** send FROM your Gmail **TO the officer** (not you).")

# Your Gmail (worker – sends FROM)
sidebar_email = st.sidebar.text_input("Your Gmail:", value="", key="test_email_sender", placeholder="you@gmail.com")
sidebar_password = st.sidebar.text_input("App Password", value="", key="test_email_password", type="password", placeholder="16-char Gmail App Password")

# Officer email (recipient – NOT you) – where the full report is sent
sidebar_officer_email = st.sidebar.text_input("Officer email:", value="", key="officer_email_recipient", placeholder="officer@company.com", help="Report is sent TO this address for analysis")

def build_report_for_officer():
    """Full report for officer: where anomalies are detected and how many."""
    lines = [
        "MARITIME CYBERSECURITY – FULL ANOMALY REPORT FOR OFFICER",
        "Generated: " + datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "",
        "========== ANOMALY COUNTS (HOW MANY) ==========",
        "",
        f"Total login records scanned: {len(merged_df)}",
        f"ANOMALIES – Suspicious IPs flagged: {len(flagged_ips)}",
        f"ANOMALIES – Consecutive failed logins (≥3): {len(suspicious)}",
    ]
    mal_hits = merged_df[merged_df.get("Is_Malicious_IP", False)]
    if not mal_hits.empty:
        lines.append(f"ANOMALIES – Logins from malicious/blocklist IPs: {len(mal_hits)}")
    lines.append("")
    if "Threat_Level" in merged_df.columns:
        high = (merged_df["Threat_Level"] == "High").sum()
        med = (merged_df["Threat_Level"] == "Medium").sum()
        lines.append(f"Threat level – High: {high}, Medium: {med}")
    lines.append("")
    lines.append("========== WHERE ANOMALIES ARE DETECTED ==========")
    lines.append("")
    if not flagged_ips.empty:
        lines.append("--- Suspicious IPs ---")
        for i, (_, r) in enumerate(flagged_ips.iterrows(), 1):
            lines.append(f"  {i}. IP {r['IP']} – fail count: {int(r.get('Fail_Count', 0))}, users: {int(r.get('Unique_Users', 0))}, ships: {int(r.get('Unique_Ships', 0))}")
        lines.append("")
    if not suspicious.empty:
        lines.append("--- Consecutive failed logins ---")
        for i, (_, r) in enumerate(suspicious.iterrows(), 1):
            lines.append(f"  {i}. Ship {r['Ship_ID']}, user '{r['Username']}' – {int(r.get('Consec_Fails', 0))} consecutive fails, IP: {r.get('IP', 'N/A')}")
        lines.append("")
    if not mal_hits.empty:
        lines.append("--- Malicious/blocklist IP logins ---")
        for i, (_, r) in enumerate(mal_hits.head(50).iterrows(), 1):
            lines.append(f"  {i}. Ship {r['Ship_ID']}, user '{r['Username']}', IP {r['IP']}")
        if len(mal_hits) > 50:
            lines.append(f"  ... and {len(mal_hits) - 50} more.")
        lines.append("")
    if "Threat_Level" in merged_df.columns:
        lines.append("--- Anomalies by ship ---")
        for sid in sorted(merged_df["Ship_ID"].dropna().unique()):
            ship_susp = suspicious[suspicious["Ship_ID"] == sid]
            ship_high = merged_df[(merged_df["Ship_ID"] == sid) & (merged_df["Threat_Level"] == "High")]
            ship_fails = merged_df[(merged_df["Ship_ID"] == sid) & (merged_df["Login_Status"] == "Fail")]
            if not ship_susp.empty or not ship_high.empty or len(ship_fails) > 5:
                lines.append(f"  Ship {sid}: failed logins {len(ship_fails)}, suspicious events {len(ship_susp)}, high-threat {len(ship_high)}")
        lines.append("")
    else:
        lines.append("--- Anomalies by ship ---")
        for sid in sorted(merged_df["Ship_ID"].dropna().unique()):
            ship_susp = suspicious[suspicious["Ship_ID"] == sid]
            ship_fails = merged_df[(merged_df["Ship_ID"] == sid) & (merged_df["Login_Status"] == "Fail")]
            if not ship_susp.empty or len(ship_fails) > 5:
                lines.append(f"  Ship {sid}: failed logins {len(ship_fails)}, suspicious events {len(ship_susp)}")
        lines.append("")
    if os.path.exists(ALERT_HISTORY_FILE):
        ah = pd.read_csv(ALERT_HISTORY_FILE)
        recent = ah.tail(30)
        lines.append("========== RECENT ALERTS ==========")
        for _, row in recent.iterrows():
            lines.append(f"  [{row.get('Timestamp', '')}] {row.get('Alert', '')}")
    return "\n".join(lines)

# Send full report to officer
if st.sidebar.button("📤 Send report to officer", type="primary"):
    officer = (sidebar_officer_email or "").strip()
    sender = (sidebar_email or "").strip() or EMAIL_SENDER
    password = (sidebar_password or "").strip() or EMAIL_PASSWORD
    if not officer:
        st.sidebar.error("Enter **Officer email (recipient)** above first.")
    elif not sender or not password:
        st.sidebar.error("Enter **Your Gmail** and **App Password** above first.")
    else:
        try:
            report_body = build_report_for_officer()
            send_email_alert("Maritime Cybersecurity Report – for analysis", report_body, receiver=officer, force_send=True, sender=sender, password=password)
            st.sidebar.success("Report sent to officer. They can analyse it from their inbox.")
        except Exception as e:
            st.sidebar.error(f"Send failed: {e}")

# Test email (to officer if entered, else default)
if st.sidebar.button("Test Email"):
    sender = (sidebar_email.strip() or EMAIL_SENDER)
    password = (sidebar_password.strip() or EMAIL_PASSWORD)
    receiver = (sidebar_officer_email or "").strip() or EMAIL_RECEIVER
    if not sender or not password:
        st.sidebar.warning("Enter your Gmail and App Password above.")
    else:
        try:
            send_email_alert("Test Alert", "This is a test from the Maritime Dashboard.", receiver=receiver or None, force_send=True, sender=sender, password=password)
            st.sidebar.success("Test email sent." + (" To officer." if receiver else ""))
        except Exception as e:
            st.sidebar.error(f"Test failed: {e}")

st.title("🛳️ Maritime Cybersecurity Dashboard (with Simple Blockchain)")

# Show main data
st.subheader("All Login Logs (merged with AIS where available)")
st.dataframe(merged_df)

st.subheader("IP Summary (fail counts / unique users / ships)")
if not ip_summary.empty:
    st.dataframe(ip_summary.sort_values("Fail_Count", ascending=False).reset_index(drop=True))
else:
    st.info("No valid IP summary data.")

st.subheader("🚩 Flagged Suspicious IPs")
if not flagged_ips.empty:
    st.dataframe(flagged_ips)
else:
    st.success("No suspicious IPs detected.")

st.subheader("⚠️ Suspicious Login Attempts (Consecutive fails)")
if not suspicious.empty:
    st.dataframe(suspicious)
else:
    st.success("No suspicious consecutive login attempts.")

# Threat scoring
def threat_score(row, flagged_ip_set):
    score = 0
    if row.get("Consec_Fails", 0) >= 3: score += 2
    if row.get("Is_Malicious_IP"): score += 3
    if pd.notna(row.get("AIS_Lat")) and pd.notna(row.get("AIS_Lon")) and row.get("Login_Status") == "Fail":
        score += 1
    if pd.notna(row.get("IP")) and str(row.get("IP")) in flagged_ip_set:
        score += 2
    return score

flagged_set = set(flagged_ips["IP"].astype(str).tolist()) if not flagged_ips.empty else set()
merged_df["Threat_Score"] = merged_df.apply(lambda r: threat_score(r, flagged_set), axis=1)
merged_df["Threat_Level"] = merged_df["Threat_Score"].apply(lambda x: "High" if x >= 4 else ("Medium" if x >= 2 else "Low"))

st.subheader("Threat Scores")
st.dataframe(merged_df[["Ship_ID","Username","IP","Login_Status","Consec_Fails","Is_Malicious_IP","Threat_Score","Threat_Level"]])

# Visualizations
st.subheader("📊 Failed Logins per Ship")
failed_logins = merged_df[merged_df["Login_Status"] == "Fail"].groupby("Ship_ID").size().reset_index(name="Failed_Logins")
if not failed_logins.empty:
    fig = px.bar(failed_logins, x="Ship_ID", y="Failed_Logins", color="Failed_Logins", title="Failed Logins per Ship")
    st.plotly_chart(fig)
else:
    st.info("No failed logins yet.")

st.subheader("📈 Historical Failed Login Trend")
try:
    daily_failed = merged_df[merged_df["Login_Status"] == "Fail"].groupby(merged_df["Timestamp"].dt.date).size().reset_index(name="Failed_Logins")
    fig_trend = px.line(daily_failed, x="Timestamp", y="Failed_Logins", title="Daily Failed Logins Trend", markers=True)
    st.plotly_chart(fig_trend)
except Exception:
    st.info("Not enough timestamp data for historical trend.")

# AIS map
st.subheader("🗺️ AIS Positions (latest per ship)")
if not ais_df.empty:
    latest_ais = ais_df.sort_values("Timestamp").groupby("Ship_ID").tail(1)
    m = folium.Map(location=[20,75], zoom_start=4)
    for _, r in latest_ais.iterrows():
        folium.Marker([r["Latitude"], r["Longitude"]], popup=f"Ship {r['Ship_ID']}", icon=folium.Icon(color="blue")).add_to(m)
    folium_static(m)
    st.dataframe(latest_ais)
else:
    st.info("No AIS data available.")

# Flagged IP geolocation
st.subheader("📍 Flagged IP Locations (geolocated)")
if not flagged_ips.empty:
    m_ips = folium.Map(location=[20,75], zoom_start=3)
    def load_geo_cache():
        if os.path.exists(GEO_CACHE_FILE):
            try:
                with open(GEO_CACHE_FILE, "r") as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}
    def save_geo_cache(c):
        try:
            with open(GEO_CACHE_FILE, "w") as f:
                json.dump(c, f, indent=2)
        except Exception:
            pass
    geo_cache = load_geo_cache()
    for ip in flagged_ips["IP"].astype(str).tolist():
        geo = None
        if ip in geo_cache:
            geo = geo_cache[ip]
        else:
            try:
                resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=5).json()
                if resp.get("status") == "success":
                    geo = {"lat": resp.get("lat"), "lon": resp.get("lon"), "city": resp.get("city"), "country": resp.get("country")}
            except Exception:
                geo = None
            if geo:
                geo_cache[ip] = geo
                save_geo_cache(geo_cache)
        if geo and geo.get("lat") and geo.get("lon"):
            folium.Marker([geo["lat"], geo["lon"]], popup=f"{ip}\n{geo.get('city')}, {geo.get('country')}", icon=folium.Icon(color="red")).add_to(m_ips)
    folium_static(m_ips)
else:
    st.info("No flagged IPs to geolocate.")

# Blocklist UI
st.subheader("🔒 IP Blocklist Management")
new_block_ip = st.text_input("Add IP to blocklist")
if st.button("Block IP"):
    if is_valid_ip(new_block_ip):
        blocklist = set()
        if os.path.exists(BLOCKLIST_FILE):
            try:
                with open(BLOCKLIST_FILE, "r") as f:
                    blocklist = set(json.load(f))
            except Exception:
                blocklist = set()
        blocklist.add(new_block_ip)
        with open(BLOCKLIST_FILE, "w") as f:
            json.dump(list(blocklist), f, indent=2)
        st.success(f"Blocked {new_block_ip}")
    else:
        st.error("Invalid IP")

if os.path.exists(BLOCKLIST_FILE):
    try:
        with open(BLOCKLIST_FILE, "r") as f:
            bl = json.load(f)
    except Exception:
        bl = []
else:
    bl = []
if bl:
    st.write("Blocked IPs:")
    st.write(bl)

if bl:
    blocked_hits = merged_df[merged_df["IP"].isin(bl)]
    if not blocked_hits.empty:
        st.subheader("🔴 Blocked IP Attempts")
        st.dataframe(blocked_hits)
        for _, row in blocked_hits.iterrows():
            send_alert(f"Blocked IP {row['IP']} attempted login on Ship {row['Ship_ID']}, user {row['Username']}", email=False, record_blockchain=True)

# Alert history
st.subheader("📜 Alert History")
if os.path.exists(ALERT_HISTORY_FILE):
    ah = pd.read_csv(ALERT_HISTORY_FILE)
    ah["Timestamp"] = pd.to_datetime(ah["Timestamp"], errors="coerce")
    st.dataframe(ah.sort_values("Timestamp", ascending=False))
else:
    st.info("No alerts triggered yet.")

# ---------------- EXCEL DOWNLOAD (fixed) ----------------
st.subheader("📄 Download Threat Report (Excel or CSV)")
report_bytes = to_excel_bytes(merged_df)
is_excel = report_bytes[:2] == b"PK"
st.download_button(
    label="⬇️ Download Full Threat Report",
    data=report_bytes,
    file_name="threat_report.xlsx" if is_excel else "threat_report.csv",
    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" if is_excel else "text/csv"
)

# ---------------- BLOCKCHAIN UI ----------------
st.subheader("🔗 Blockchain Ledger (alerts recorded as blocks)")
if st.button("Verify Blockchain Integrity"):
    errors = blockchain.verify_chain()
    if not errors:
        st.success("Blockchain verified: no integrity problems found.")
    else:
        st.error("Blockchain integrity issues:\n" + "\n".join(errors))

# Display blockchain table (latest first)
if blockchain.chain:
    df_chain = pd.DataFrame(list(reversed(blockchain.chain)))  # show latest on top
    st.dataframe(df_chain[["index", "timestamp", "data", "prev_hash", "hash"]])

# Option: export blockchain ledger
if st.button("Export Blockchain Ledger (JSON)"):
    try:
        with open(BLOCKCHAIN_FILE, "r") as f:
            data = f.read()
        st.download_button("⬇️ Download blockchain_ledger.json", data=data, file_name="blockchain_ledger.json", mime="application/json")
    except Exception as e:
        st.error(f"Failed to export blockchain: {e}")

st.markdown("**Notes:** Replace EMAIL_SENDER and EMAIL_PASSWORD with your Gmail and App Password. For production, use environment variables or Streamlit secrets. The blockchain here is a simple append-only ledger for demonstration and evidence recording; it's not a distributed blockchain.")

# Clean shutdown
try:
    observer.stop()
except Exception:
    pass
