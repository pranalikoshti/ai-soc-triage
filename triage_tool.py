"""
triage_tool.py
Core orchestrator: Splunk → IOC extraction → VirusTotal → AI → Report
"""
import os, re, json, time, requests
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

load_dotenv()
# DEBUG — remove after fixing
print(f"DEBUG user: '{os.getenv('SPLUNK_USER')}'")
print(f"DEBUG pass: '{os.getenv('SPLUNK_PASS')}'")
print(f"DEBUG host: '{os.getenv('SPLUNK_HOST')}'")

SPLUNK_HOST  = os.getenv("SPLUNK_HOST", "localhost")
SPLUNK_PORT  = os.getenv("SPLUNK_PORT", "8089")
SPLUNK_INDEX = os.getenv("SPLUNK_INDEX", "alerts")
VT_API_KEY   = os.getenv("VT_API_KEY")

REPORT_DIR = Path("reports")
REPORT_DIR.mkdir(exist_ok=True)

# Regex patterns for IOC extraction
IP_RE = re.compile(
    r'\b((?!10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|127\.|0\.)'
    r'(?:\d{1,3}\.){3}\d{1,3})\b')
# Excludes RFC1918 private ranges and loopback — only flags public IPs

DOMAIN_RE = re.compile(
    r'\b(?:[a-zA-Z0-9-]{1,63}\.)+(?:com|net|org|io|co|ru|cn|xyz'
    r'|top|info|biz|club|online|site|tech|me)\b')


SPLUNK_USER  = os.getenv("SPLUNK_USER", "admin")
SPLUNK_PASS  = os.getenv("SPLUNK_PASS")

def splunk_search(query, earliest="-24h@h"):
    url = f"https://{SPLUNK_HOST}:{SPLUNK_PORT}/services/search/jobs"
    payload = {
        "search":        f"search {query}",
        "earliest_time":  earliest,
        "latest_time":   "now",
        "output_mode":   "json",
        "exec_mode":     "oneshot",
        "count":         50
    }
    try:
        resp = requests.post(
            url,
            auth=(SPLUNK_USER, SPLUNK_PASS),   # basic auth — no token needed
            data=payload,
            verify=False,
            timeout=30)
        resp.raise_for_status()
        return resp.json().get("results", [])
    except requests.exceptions.ConnectionError:
        print("[!] Cannot connect to Splunk.")
        print("    Is Splunk running? Start menu → Splunk Enterprise → Start Splunk")
        return []
    except requests.exceptions.HTTPError as e:
        print(f"[!] Splunk API error: {e}")
        if "401" in str(e):
            print("    Fix: check SPLUNK_USER and SPLUNK_PASS in .env")
        return []



def get_alerts():
    """Pull HIGH and CRITICAL alerts from Splunk."""
    print("[*] Querying Splunk for high-severity alerts...")

    # This SPL works with the test_alerts.json data uploaded to Splunk
    # Adjust field names if using real home lab data
    query = (f'index={SPLUNK_INDEX} '
             f'(severity=HIGH OR severity=CRITICAL OR severity=high OR severity=critical) '
             f'| eval src=coalesce(src_ip, src) '
             f'| eval dest=coalesce(dest_ip, dest) '
             f'| eval sig=coalesce(alert_signature, "alert.signature", sourcetype) '
             f'| table _time, severity, sig, src, dest, dest_port, host, sourcetype, category')

    alerts = splunk_search(query)
    print(f"    Found: {len(alerts)} alerts")
    return alerts


def extract_iocs(alerts):
    """
    Pull unique public IPs and suspicious domains from all alert fields.
    Skips private IP ranges — those are internal and not VirusTotal-lookupable.
    """
    ips, domains = set(), set()
    for alert in alerts:
        text = json.dumps(alert)
        ips.update(IP_RE.findall(text))
        domains.update(DOMAIN_RE.findall(text))
    iocs = [("ip", ip) for ip in ips] + [("domain", d) for d in domains]
    print(f"    Extracted: {len(ips)} public IPs, {len(domains)} domains")
    return iocs

def vt_lookup(ioc_type, value):
    """
    Query VirusTotal for an IP or domain.
    Returns dict: malicious count, suspicious count, threat categories.
    Free tier: 4 requests/minute — caller must enforce rate limiting.
    """
    if ioc_type == "ip":
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{value}"
    else:
        url = f"https://www.virustotal.com/api/v3/domains/{value}"

    headers = {"x-apikey": VT_API_KEY}
    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 404:
            return {"malicious": 0, "suspicious": 0, "categories": [], "found": False}
        if r.status_code == 429:
            print("    [!] VirusTotal rate limit hit — waiting 20s...")
            time.sleep(20)
            return vt_lookup(ioc_type, value)   # retry once
        r.raise_for_status()
        attrs = r.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        cats  = list(attrs.get("categories", {}).values())
        return {
            "malicious":  stats.get("malicious",  0),
            "suspicious": stats.get("suspicious", 0),
            "categories": cats[:3],
            "found":      True
        }
    except Exception as e:
        return {"malicious": 0, "suspicious": 0, "categories": [],
                "found": False, "error": str(e)}
				


def enrich_iocs(iocs):
    """Look up all IOCs in VirusTotal with rate limiting."""
    if not iocs:
        return {}
    print(f"\n[*] Enriching {len(iocs)} IOCs via VirusTotal...")
    print(f"    Rate limit: 4/min → ~{len(iocs) * 16}s estimated")
    enriched = {}
    for i, (ioc_type, value) in enumerate(iocs):
        result = vt_lookup(ioc_type, value)
        enriched[value] = {"type": ioc_type, "value": value, **result}
        flag = " [MALICIOUS]" if result["malicious"] > 0 else ""
        print(f"    [{i+1}/{len(iocs)}] {value}: "
              f"malicious={result['malicious']}, "
              f"suspicious={result['suspicious']}{flag}")
        if i < len(iocs) - 1:
            time.sleep(16)   # 16s = safely under 4/min limit
    return enriched


def priority_score(alert, enriched):
    """
    Composite score used to rank alerts in the report.
    Higher = more urgent.
    Formula: severity_weight + (vt_malicious × 5) + (vt_suspicious × 1)
    """
    weights = {"critical": 30, "high": 20, "medium": 10, "low": 5}
    sev = str(alert.get("severity", "low")).lower()
    score = weights.get(sev, 5)

    text = json.dumps(alert)
    for value, vt in enriched.items():
        if value in text:
            score += vt.get("malicious", 0) * 5
            score += vt.get("suspicious", 0) * 1
    return score