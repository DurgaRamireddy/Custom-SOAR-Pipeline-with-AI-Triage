import json
import os
from datetime import datetime, timezone


LOG_FILE = "results/soar_audit_log.jsonl"


def execute(alert: dict, enrichment: dict, triage: dict, decision: dict) -> dict:
    """
    Executes the decision made by decision_engine.py.
    Every execution is logged with the full reasoning chain regardless of outcome.
    Returns a result dict summarizing what was done.
    """
    action = decision.get("action")

    if action == "AUTO_CLOSE":
        return _auto_close(alert, enrichment, triage, decision)
    elif action == "ESCALATE":
        return _escalate(alert, enrichment, triage, decision)
    else:
        return _log_error(alert, decision, f"Unknown action: {action}")


def _auto_close(alert, enrichment, triage, decision) -> dict:
    """
    Logs the alert as closed. No case created.
    Full reasoning chain is preserved for human review and rule tuning.
    """
    result = {
        "status": "AUTO_CLOSED",
        "alert_id": decision["alert_id"],
        "attack_type": decision["attack_type"],
        "rule_fired": decision["rule_fired"],
        "reason": decision["reason"],
        "severity": decision["severity"],
        "false_positive_probability": decision["false_positive_probability"],
        "verdict": decision["verdict"],
        "ai_summary": triage.get("evidence_summary"),
        "recommended_actions": triage.get("recommended_actions"),
        "enrichment_scope": enrichment.get("scope"),
        "closed_at": datetime.now(timezone.utc).isoformat()
    }
    _write_log(result)
    return result


def _escalate(alert, enrichment, triage, decision) -> dict:
    """
    Escalates the alert. Logs the decision and attempts TheHive case creation.
    TheHive client is stubbed until TheHive is installed.
    """
    # Build the case payload — this is what TheHive will receive
    case_payload = {
        "alert_id": decision["alert_id"],
        "attack_type": decision["attack_type"],
        "severity": decision["severity"],
        "verdict": decision["verdict"],
        "rule_fired": decision["rule_fired"],
        "reason": decision["reason"],
        "ai_summary": triage.get("evidence_summary"),
        "recommended_actions": triage.get("recommended_actions"),
        "iocs": triage.get("iocs", []),
        "mitre_technique": triage.get("mitre_technique"),
        "attack_stage": triage.get("attack_stage"),
        "enrichment": enrichment,
        "raw_alert": alert
    }

    # Stub: replace this with real TheHive call once installed
    thehive_result = _thehive_stub(case_payload)

    result = {
        "status": "ESCALATED",
        "alert_id": decision["alert_id"],
        "attack_type": decision["attack_type"],
        "rule_fired": decision["rule_fired"],
        "reason": decision["reason"],
        "severity": decision["severity"],
        "verdict": decision["verdict"],
        "thehive_case": thehive_result,
        "escalated_at": datetime.now(timezone.utc).isoformat()
    }
    _write_log(result)
    return result


def _thehive_stub(case_payload: dict) -> dict:
    """
    Placeholder for real TheHive API call.
    Prints what would be sent and returns a fake case ID.
    Replace the body of this function with thehive_client.create_case(case_payload)
    once TheHive is installed.
    """
    print(f"  [TheHive STUB] Would create case for alert_id: {case_payload['alert_id']}")
    print(f"  [TheHive STUB] Title: {case_payload['attack_type']} — {case_payload['severity']}")
    return {
        "stub": True,
        "case_id": f"STUB-{case_payload['alert_id'][:8].upper()}",
        "message": "TheHive not yet installed — stub response"
    }


def _log_error(alert, decision, message) -> dict:
    """
    Logs an unexpected error in the pipeline without crashing.
    """
    result = {
        "status": "ERROR",
        "alert_id": decision.get("alert_id", "unknown"),
        "error": message,
        "logged_at": datetime.now(timezone.utc).isoformat()
    }
    _write_log(result)
    return result


def _write_log(record: dict):
    """
    Appends a record to the audit log as a single JSON line (JSONL format).
    JSONL means one complete JSON object per line — easy to grep, easy to parse,
    and new records don't require rewriting the whole file.
    """
    os.makedirs("results", exist_ok=True)
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(record) + "\n")


if __name__ == "__main__":
    # Test all three scenarios: AUTO_CLOSE, ESCALATE (splunk), ESCALATE (honeytoken)
    test_cases = [
        {
            "label": "AUTO_CLOSE — real Kerberoasting, low confidence",
            "alert": {"alert_id": "test-001", "attack_type": "Kerberoasting", "source": "splunk"},
            "enrichment": {"scope": "private", "external_lookup": "skipped"},
            "triage": {
                "severity": "Medium",
                "verdict": "Requires Investigation",
                "false_positive_probability": 45,
                "escalate": True,
                "evidence_summary": "RC4 Kerberos TGS request from jsmith — missing event code limits certainty.",
                "recommended_actions": ["Review TGS history", "Audit mjones SPN"],
                "iocs": ["jsmith@LAB.LOCAL", "192.168.255.135"],
                "mitre_technique": "T1558.003 - Kerberoasting",
                "attack_stage": "Credential Access"
            },
            "decision": {
                "alert_id": "test-001",
                "attack_type": "Kerberoasting",
                "action": "AUTO_CLOSE",
                "rule_fired": "Default: no escalation rule met",
                "reason": "Severity Medium, FP probability 45% — does not meet escalation threshold.",
                "severity": "Medium",
                "false_positive_probability": 45,
                "verdict": "Requires Investigation"
            }
        },
        {
            "label": "ESCALATE — synthetic Tor exit node, high confidence",
            "alert": {"alert_id": "synthetic-001", "attack_type": "Kerberoasting", "source": "splunk"},
            "enrichment": {
                "scope": "public",
                "virustotal": {"malicious": 16, "suspicious": 2},
                "abuseipdb": {"abuse_score": 77, "total_reports": 88}
            },
            "triage": {
                "severity": "High",
                "verdict": "Likely True Positive",
                "false_positive_probability": 15,
                "escalate": True,
                "evidence_summary": "TGS request from Tor exit node 185.220.101.47 with RC4 encryption.",
                "recommended_actions": ["Reset svc_backup_admin password", "Block 185.220.101.47"],
                "iocs": ["svc_backup_admin@LAB.LOCAL", "185.220.101.47"],
                "mitre_technique": "T1558.003 - Kerberoasting",
                "attack_stage": "Credential Access"
            },
            "decision": {
                "alert_id": "synthetic-001",
                "attack_type": "Kerberoasting",
                "action": "ESCALATE",
                "rule_fired": "Rule 2: AI escalation + strict threshold",
                "reason": "FP probability 15% below strict threshold of 20%.",
                "severity": "High",
                "false_positive_probability": 15,
                "verdict": "Likely True Positive"
            }
        },
        {
            "label": "ESCALATE — honeytoken, bypassed AI",
            "alert": {"alert_id": "honeytoken-001", "attack_type": "Honeytoken Access", "source": "honeytoken"},
            "enrichment": {"scope": "private", "external_lookup": "skipped"},
            "triage": {
                "severity": "High",
                "verdict": "Requires Investigation",
                "false_positive_probability": 15,
                "escalate": True,
                "evidence_summary": "svc_backup_admin accessed via network logon.",
                "recommended_actions": ["Investigate source host", "Review auth logs"],
                "iocs": ["svc_backup_admin", "192.168.255.135"],
                "mitre_technique": "T1078 - Valid Accounts",
                "attack_stage": "Lateral Movement"
            },
            "decision": {
                "alert_id": "honeytoken-001",
                "attack_type": "Honeytoken Access",
                "action": "ESCALATE",
                "rule_fired": "Rule 1: Honeytoken",
                "reason": "Honeytoken triggered — definitionally malicious.",
                "severity": "High",
                "false_positive_probability": 0,
                "verdict": "True Positive"
            }
        }
    ]

    for case in test_cases:
        print(f"\n--- {case['label']} ---")
        result = execute(
            case["alert"],
            case["enrichment"],
            case["triage"],
            case["decision"]
        )
        print(f"  Status:     {result['status']}")
        print(f"  Rule fired: {result['rule_fired']}")
        if result["status"] == "ESCALATED":
            print(f"  TheHive:    {result['thehive_case']}")

    print(f"\nAudit log written to: {LOG_FILE}")
    print("Contents:")
    with open(LOG_FILE) as f:
        for line in f:
            record = json.loads(line)
            print(f"  {record['status']} | {record['alert_id']} | {record.get('closed_at') or record.get('escalated_at') or record.get('logged_at')}")
