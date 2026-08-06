import json
import time
from datetime import datetime, timezone

from enrichment import extract_ioc, normalize_ip, check_virustotal_ip, check_abuseipdb
from ai_triage import triage_alert
from decision_engine import decide
from response_actions import execute


ALERTS_FILE = "alerts/normalized_alerts.json"
SYNTHETIC_FILE = "alerts/synthetic_test_alerts.json"
RESULTS_FILE = "results/pipeline_results.json"
RATE_LIMIT_DELAY = 16  # seconds between alerts — respects VT's 4/min free tier


def enrich_alert(alert: dict) -> dict:
    """
    Runs the full enrichment chain for a single alert.
    Returns a structured enrichment bundle regardless of IP type.
    """
    ioc = extract_ioc(alert)

    if not ioc["has_ip"]:
        return {
            "scope": "unknown",
            "reason": ioc.get("reason"),
            "external_lookup": "skipped"
        }

    norm = normalize_ip(ioc["raw_ip"])

    if norm["scope"] != "public":
        return {
            "scope": norm["scope"],
            "cleaned_ip": norm["cleaned"],
            "external_lookup": "skipped — private IP"
        }

    # Public IP — run all external lookups
    cleaned = norm["cleaned"]
    return {
        "scope": "public",
        "cleaned_ip": cleaned,
        "virustotal": check_virustotal_ip(cleaned),
        "abuseipdb": check_abuseipdb(cleaned)
    }


def run_pipeline(alerts: list, label: str = "") -> list:
    """
    Runs the full SOAR pipeline for a list of alerts.
    Returns a list of complete result records.
    """
    results = []
    total = len(alerts)

    print(f"\n{'='*60}")
    print(f"Running pipeline: {label} ({total} alerts)")
    print(f"{'='*60}")

    for i, alert in enumerate(alerts, 1):
        alert_id = alert.get("alert_id", "unknown")
        attack_type = alert.get("attack_type", "unknown")
        is_synthetic = alert.get("synthetic", False)

        print(f"\n[{i}/{total}] {attack_type} | {alert_id}")

        # Step 1: Enrich
        print("  → Step 1: Enriching...")
        enrichment = enrich_alert(alert)
        print(f"     scope: {enrichment['scope']}")

        # Step 2: AI Triage
        print("  → Step 2: AI triage...")
        triage_result = triage_alert(alert, enrichment)
        triage = triage_result["ai_triage"]
        print(f"     severity: {triage.get('severity')} | "
              f"verdict: {triage.get('verdict')} | "
              f"FP prob: {triage.get('false_positive_probability')}%")

        # Step 3: Decision
        print("  → Step 3: Decision engine...")
        decision = decide(alert, enrichment, triage)
        print(f"     action: {decision['action']} | rule: {decision['rule_fired']}")

        # Step 4: Execute + log
        print("  → Step 4: Response action...")
        response = execute(alert, enrichment, triage, decision)
        print(f"     status: {response['status']}")

        # Combine everything into one complete record
        results.append({
            "alert": alert,
            "enrichment": enrichment,
            "ai_triage": triage,
            "decision": decision,
            "response": response,
            "processed_at": datetime.now(timezone.utc).isoformat()
        })

        # Rate limiting — VT free tier allows 4 requests/min
        # Only pause if this wasn't the last alert
        if i < total:
            if enrichment["scope"] == "public":
                print(f"  → Pausing {RATE_LIMIT_DELAY}s (VT rate limit)...")
                time.sleep(RATE_LIMIT_DELAY)
            else:
                time.sleep(1)  # gentle pause even for private IPs

    return results


if __name__ == "__main__":
    # Load real alerts
    with open(ALERTS_FILE) as f:
        real_alerts = json.load(f)

    # Load synthetic alerts
    with open(SYNTHETIC_FILE) as f:
        synthetic_alerts = json.load(f)

    # Run pipeline on both
    all_results = []
    all_results += run_pipeline(real_alerts, label="Real lab alerts")
    all_results += run_pipeline(synthetic_alerts, label="Synthetic test alerts")

    # Save complete results
    with open(RESULTS_FILE, "w") as f:
        json.dump(all_results, f, indent=2)

    # Print summary
    total = len(all_results)
    escalated = sum(1 for r in all_results if r["response"]["status"] == "ESCALATED")
    auto_closed = sum(1 for r in all_results if r["response"]["status"] == "AUTO_CLOSED")

    print(f"\n{'='*60}")
    print(f"Pipeline complete — {total} alerts processed")
    print(f"  ESCALATED:   {escalated}")
    print(f"  AUTO_CLOSED: {auto_closed}")
    print(f"  Results:     {RESULTS_FILE}")
    print(f"  Audit log:   results/soar_audit_log.jsonl")
    print(f"{'='*60}")
