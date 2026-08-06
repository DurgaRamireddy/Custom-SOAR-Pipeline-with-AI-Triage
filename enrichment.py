import os
import ipaddress
import requests
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")


def extract_ioc(alert: dict) -> dict:
    """
    Safely extracts the observable IP from an alert, regardless of
    whether the field is missing, null, or contains a placeholder
    like 'unknown' instead of an actual address.
    """
    raw_ip = alert.get("source_ip")
    if not raw_ip or raw_ip == "unknown":
        return {"has_ip": False, "reason": "no usable source_ip in alert"}
    return {"has_ip": True, "raw_ip": raw_ip}


def normalize_ip(raw_ip: str) -> dict:
    """
    Cleans an IP string (strips IPv4-mapped IPv6 wrapper) and classifies
    it as private or public. Private IPs have no public reputation data,
    so this gates whether external lookups are even worth attempting.
    """
    cleaned = raw_ip.replace("::ffff:", "")
    try:
        ip_obj = ipaddress.ip_address(cleaned)
    except ValueError:
        return {"original": raw_ip, "cleaned": cleaned, "valid": False, "scope": "unknown"}
    return {
        "original": raw_ip,
        "cleaned": cleaned,
        "valid": True,
        "scope": "private" if ip_obj.is_private else "public"
    }


def check_virustotal_ip(ip: str) -> dict:
    """
    Looks up a public IP's reputation on VirusTotal. Only call this
    when normalize_ip() has confirmed scope == "public".
    """
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_API_KEY}
    try:
        response = requests.get(url, headers=headers, timeout=10)
    except requests.exceptions.RequestException as e:
        return {"error": f"Request failed: {str(e)}"}
    if response.status_code == 404:
        return {"found": False, "reason": "Not in VirusTotal's database"}
    if response.status_code != 200:
        return {"error": f"VirusTotal returned status {response.status_code}"}
    data = response.json()
    stats = data["data"]["attributes"]["last_analysis_stats"]
    return {
        "found": True,
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0)
    }


def check_abuseipdb(ip: str) -> dict:
    """
    Checks an IP's abuse history via AbuseIPDB.
    Returns confidence score (0-100), total reports, and last reported date.
    Only call this for public IPs.
    """
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
    except requests.exceptions.RequestException as e:
        return {"error": f"Request failed: {str(e)}"}
    if response.status_code != 200:
        return {"error": f"AbuseIPDB returned status {response.status_code}"}
    data = response.json().get("data", {})
    return {
        "abuse_score": data.get("abuseConfidenceScore", 0),
        "total_reports": data.get("totalReports", 0),
        "last_reported": data.get("lastReportedAt", None),
        "isp": data.get("isp", None)
    }


if __name__ == "__main__":
    import json

    # Test against real alerts
    with open("alerts/normalized_alerts.json") as f:
        real_alerts = json.load(f)

    # Test against synthetic public-IP alerts
    with open("alerts/synthetic_test_alerts.json") as f:
        synthetic_alerts = json.load(f)

    all_alerts = real_alerts + synthetic_alerts
    seen_types = set()

    for alert in all_alerts:
        label = "[SYNTHETIC] " if alert.get("synthetic") else "[REAL] "
        key = f"{alert['attack_type']}_{alert.get('synthetic', False)}"
        if key in seen_types:
            continue
        seen_types.add(key)

        print(f"\n--- {label}{alert['attack_type']} (alert_id: {alert['alert_id']}) ---")
        ioc = extract_ioc(alert)
        print(f"  extract_ioc:  {ioc}")

        if ioc["has_ip"]:
            norm = normalize_ip(ioc["raw_ip"])
            print(f"  normalize_ip: {norm}")
            if norm["scope"] == "public":
                print(f"  VirusTotal:   {check_virustotal_ip(norm['cleaned'])}")
                print(f"  AbuseIPDB:    {check_abuseipdb(norm['cleaned'])}")
            else:
                print("  Skipping external lookups (not public)")
