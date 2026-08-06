from datetime import datetime, timezone

# Confidence thresholds
FP_THRESHOLD_STRICT = 20   # AI flagged + below this = escalate
FP_THRESHOLD_LOOSE = 40    # High/Critical severity + below this = escalate
HIGH_SEVERITY = {"Critical", "High"}


def decide(alert: dict, enrichment: dict, triage: dict) -> dict:
    """
    Takes the alert, enrichment bundle, and AI triage verdict.
    Applies routing rules in priority order and returns a decision.
    Action is either ESCALATE (create TheHive case) or AUTO_CLOSE (log and done).

    Rule priority:
        1. Honeytoken source → always escalate, AI verdict ignored
        2. AI flagged for escalation + FP prob below strict threshold → escalate
        3. High/Critical severity + FP prob below loose threshold → escalate
        4. Everything else → auto-close
    """
    alert_id = alert.get("alert_id", "unknown")
    attack_type = alert.get("attack_type", "unknown")
    source = alert.get("source", "splunk")

    severity = triage.get("severity", "Low")
    fp_prob = triage.get("false_positive_probability", 100)
    escalate_flag = triage.get("escalate", False)
    verdict = triage.get("verdict", "Likely False Positive")

    # Rule 1: Honeytoken — bypass AI verdict entirely
    # Rationale: honeytokens are traps we set ourselves. Any interaction
    # is definitionally malicious. AI triage proved it hedges here (finding #2)
    # so we route around it for this alert type.
    if source == "honeytoken":
        return _build_decision(
            alert_id=alert_id,
            attack_type=attack_type,
            action="ESCALATE",
            rule_fired="Rule 1: Honeytoken",
            reason="Honeytoken triggered — trap set by defenders, any access is definitionally malicious. AI verdict bypassed by design.",
            severity=severity,
            fp_prob=0,
            verdict="True Positive"
        )

    # Rule 2: AI confident + flagged for escalation
    if escalate_flag and fp_prob < FP_THRESHOLD_STRICT:
        return _build_decision(
            alert_id=alert_id,
            attack_type=attack_type,
            action="ESCALATE",
            rule_fired="Rule 2: AI escalation + strict threshold",
            reason=f"AI flagged for escalation with FP probability {fp_prob}% — below strict threshold of {FP_THRESHOLD_STRICT}%.",
            severity=severity,
            fp_prob=fp_prob,
            verdict=verdict
        )

    # Rule 3: High/Critical severity with reasonable confidence
    if severity in HIGH_SEVERITY and fp_prob < FP_THRESHOLD_LOOSE:
        return _build_decision(
            alert_id=alert_id,
            attack_type=attack_type,
            action="ESCALATE",
            rule_fired="Rule 3: High/Critical severity + loose threshold",
            reason=f"Severity {severity} with FP probability {fp_prob}% — below loose threshold of {FP_THRESHOLD_LOOSE}%.",
            severity=severity,
            fp_prob=fp_prob,
            verdict=verdict
        )

    # Default: auto-close
    return _build_decision(
        alert_id=alert_id,
        attack_type=attack_type,
        action="AUTO_CLOSE",
        rule_fired="Default: no escalation rule met",
        reason=f"Severity {severity}, FP probability {fp_prob}%, escalate flag {escalate_flag} — does not meet any escalation threshold.",
        severity=severity,
        fp_prob=fp_prob,
        verdict=verdict
    )


def _build_decision(alert_id, attack_type, action, rule_fired,
                    reason, severity, fp_prob, verdict) -> dict:
    """
    Builds the standardized decision dict.
    Every decision has the same shape regardless of outcome —
    this is what gets logged and passed to response_actions.py.
    """
    return {
        "alert_id": alert_id,
        "attack_type": attack_type,
        "action": action,
        "rule_fired": rule_fired,
        "reason": reason,
        "severity": severity,
        "false_positive_probability": fp_prob,
        "verdict": verdict,
        "decided_at": datetime.now(timezone.utc).isoformat()
}

if __name__ == "__main__":
    print("Running decision engine tests...\n")

    test_cases = [
        {
            "label": "Real Kerberoasting — high FP prob, should AUTO_CLOSE",
            "alert": {"alert_id": "test-001", "attack_type": "Kerberoasting", "source": "splunk"},
            "enrichment": {"scope": "private"},
            "triage": {"severity": "Medium", "verdict": "Requires Investigation",
                      "false_positive_probability": 45, "escalate": True}
        },
        {
            "label": "Synthetic Tor exit node — low FP prob, should ESCALATE via Rule 2",
            "alert": {"alert_id": "synthetic-001", "attack_type": "Kerberoasting", "source": "splunk"},
            "enrichment": {"scope": "public"},
            "triage": {"severity": "High", "verdict": "Likely True Positive",
                      "false_positive_probability": 15, "escalate": True}
        },
        {
            "label": "Honeytoken — should ESCALATE via Rule 1 regardless of triage",
            "alert": {"alert_id": "honeytoken-001", "attack_type": "Honeytoken Access", "source": "honeytoken"},
            "enrichment": {"scope": "private"},
            "triage": {"severity": "High", "verdict": "Requires Investigation",
                      "false_positive_probability": 15, "escalate": True}
        },
        {
            "label": "Low severity, high FP prob — should AUTO_CLOSE",
            "alert": {"alert_id": "test-002", "attack_type": "AS-REP Roasting", "source": "splunk"},
            "enrichment": {"scope": "private"},
            "triage": {"severity": "Low", "verdict": "Likely False Positive",
                      "false_positive_probability": 75, "escalate": False}
        }
    ]

    for case in test_cases:
        result = decide(case["alert"], case["enrichment"], case["triage"])
        print(f"--- {case['label']} ---")
        print(f"  Action:     {result['action']}")
        print(f"  Rule fired: {result['rule_fired']}")
        print(f"  Reason:     {result['reason']}")
        print(f"  Decided at: {result['decided_at']}")
        print()
