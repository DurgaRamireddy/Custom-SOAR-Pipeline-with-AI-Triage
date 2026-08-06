import anthropic
import json
import time
from dotenv import load_dotenv

load_dotenv()

client = anthropic.Anthropic()

SYSTEM_PROMPT = """
You are a Tier 1 SOC analyst assistant. You analyze SIEM alerts alongside enrichment data and produce structured triage reports.

For every alert, respond ONLY with valid JSON in this exact schema — no markdown, no preamble:
{
  "severity": "Critical | High | Medium | Low",
  "verdict": "True Positive | Likely True Positive | Requires Investigation | Likely False Positive",
  "attack_stage": "Reconnaissance | Initial Access | Execution | Persistence | Privilege Escalation | Lateral Movement | Collection | Exfiltration | Command and Control | Impact",
  "mitre_tactic": "TA00XX - Tactic Name",
  "mitre_technique": "T1XXX - Technique Name",
  "mitre_confidence": "High | Medium | Low",
  "false_positive_probability": integer between 0 and 100,
  "iocs": ["list", "of", "observed", "indicators"],
  "escalate": true or false,
  "escalation_reason": "string or null",
  "evidence_summary": "2-3 sentence analyst summary of what this alert shows",
  "recommended_actions": ["Concrete action 1", "Concrete action 2", "Concrete action 3"],
  "analyst_notes": "any caveats, confidence gaps, or missing data"
}

Rules:
- Base your analysis strictly on the alert fields and enrichment data provided.
- If a field is null or missing, lower your confidence accordingly — do not invent data.
- Never fabricate IOCs, IP addresses, or account names not present in the alert or enrichment.
- Kerberoasting = T1558.003. AS-REP Roasting = T1558.004. Pass-the-Hash / lateral SMB logon = T1550.002. Honeytoken access = T1078 - Valid Accounts.
- recommended_actions must be specific and concrete — include actual account names, IPs, or hostnames from the alert. Never write vague steps like "investigate the account."
- iocs must only contain values explicitly present in the alert or enrichment data — IPs, account names, hostnames, hashes.
- Use enrichment data (VirusTotal scores, AbuseIPDB reports, ISP info) to strengthen or weaken your confidence assessment.
"""


def triage_alert(alert: dict, enrichment: dict) -> dict:
    """
    Triages a single alert using Claude, incorporating enrichment data.
    Returns a dict containing the original alert, enrichment, and AI verdict.
    """
    combined = {
        "alert": alert,
        "enrichment": enrichment
    }
    combined_text = json.dumps(combined, indent=2)

    message = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=1024,
        system=SYSTEM_PROMPT,
        messages=[{
            "role": "user",
            "content": f"Triage this SIEM alert using the provided enrichment data:\n\n{combined_text}"
        }]
    )

    raw_response = message.content[0].text
    clean = raw_response.replace("```json", "").replace("```", "").strip()

    try:
        triage_result = json.loads(clean)
    except json.JSONDecodeError:
        triage_result = {
            "error": "Failed to parse AI response",
            "raw": raw_response
        }

    return {
        "alert": alert,
        "enrichment": enrichment,
        "ai_triage": triage_result,
        "model": "claude-sonnet-4-6"
    }


if __name__ == "__main__":
    with open("alerts/normalized_alerts.json") as f:
        real_alerts = json.load(f)

    with open("alerts/synthetic_test_alerts.json") as f:
        synthetic_alerts = json.load(f)

    # honeytoken alert is the third entry
    honeytoken_alert = synthetic_alerts[2]

    test_cases = [
        (
            real_alerts[0],
            {"scope": "private", "external_lookup": "skipped"},
            "[REAL] Kerberoasting"
        ),
        (
            synthetic_alerts[0],
            {
                "scope": "public",
                "virustotal": {"found": True, "malicious": 16, "suspicious": 2, "harmless": 44, "undetected": 29},
                "abuseipdb": {"abuse_score": 77, "total_reports": 88, "last_reported": "2026-08-05T21:00:21+00:00", "isp": "Network for Tor-Exit traffic."}
            },
            "[SYNTHETIC] Kerberoasting + Tor exit node"
        ),
        (
            honeytoken_alert,
            {"scope": "private", "external_lookup": "skipped"},
            "[HONEYTOKEN] svc_backup_admin access"
        )
    ]

    for alert, enrichment, label in test_cases:
        print(f"\n{'='*60}")
        print(f"{label}")
        print(f"{'='*60}")
        result = triage_alert(alert, enrichment)
        triage = result["ai_triage"]
        print(f"  Severity:     {triage.get('severity')}")
        print(f"  Verdict:      {triage.get('verdict')}")
        print(f"  Attack stage: {triage.get('attack_stage')}")
        print(f"  MITRE:        {triage.get('mitre_technique')}")
        print(f"  FP Prob:      {triage.get('false_positive_probability')}%")
        print(f"  IOCs:         {triage.get('iocs')}")
        print(f"  Escalate:     {triage.get('escalate')}")
        print(f"  Summary:      {triage.get('evidence_summary')}")
        print(f"  Actions:      {triage.get('recommended_actions')}")
        print(f"  Notes:        {triage.get('analyst_notes')}")
        time.sleep(1)
