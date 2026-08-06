import json
import time
import uuid
from datetime import datetime, timezone
from soar_pipeline import run_pipeline


# Honeytokens we're watching — any access to these is definitionally malicious
HONEYTOKENS = [
    "svc_backup_admin",
    "IT_Credentials"
]


def generate_honeytoken_alert(triggered_by: str, source_ip: str = "unknown",
                               account: str = "unknown", event_code: str = "4624") -> dict:
    """
    Generates a structured alert dict when a honeytoken is triggered.
    Same shape as normalized_alerts.json so the pipeline processes it identically.
    """
    return {
        "alert_id": str(uuid.uuid4()),
        "attack_type": "Honeytoken Access",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_code": event_code,
        "source_host": "WIN-I4UHLQF702E.lab.local",
        "account": account,
        "source_ip": source_ip,
        "service_name": None,
        "logon_type": "3",
        "ticket_encryption_type": None,
        "raw_message": f"Honeytoken triggered: {triggered_by} was accessed",
        "log_source": "honeytoken_watcher",
        "honeytoken_trigger": triggered_by,
        "source": "honeytoken"
    }


def simulate_honeytoken_trigger(trigger: str):
    """
    Simulates a honeytoken being triggered.
    In production: this fires when Splunk detects access to the honeytoken artifact.
    For now: manually triggered to demonstrate the pipeline path.
    """
    print(f"\n{'='*60}")
    print(f"HONEYTOKEN TRIGGERED: {trigger}")
    print(f"Time: {datetime.now(timezone.utc).isoformat()}")
    print(f"{'='*60}")

    # Generate the alert
    alert = generate_honeytoken_alert(
        triggered_by=trigger,
        source_ip="::ffff:192.168.255.135",
        account="svc_backup_admin" if "backup" in trigger else "unknown",
        event_code="4624"
    )

    print(f"\nGenerated alert: {alert['alert_id']}")
    print(f"Feeding into SOAR pipeline...\n")

    # Feed directly into the pipeline — same path as Splunk alerts
    results = run_pipeline([alert], label=f"Honeytoken: {trigger}")
    return results


if __name__ == "__main__":
    print("Honeytoken Watcher — simulating triggers")
    print("In production: polls Splunk for access to honeytoken artifacts")
    print("Honeytokens monitored:", HONEYTOKENS)

    # Simulate both honeytokens being triggered
    for token in HONEYTOKENS:
        results = simulate_honeytoken_trigger(token)
        time.sleep(2)

    print("\nHoneytoken watcher complete.")
    print("Check results/soar_audit_log.jsonl for full audit trail.")
