"""
SentinelAI - AI Security Copilot Engine
Integrates Gemini LLM via environment variables (GEMINI_API_KEY) with
strict evidence grounding and a deterministic Tier-3 SOC rulebook fallback.
"""

import os
import json
from typing import Dict, Any, Optional

def generate_fallback_analysis(incident: Dict[str, Any], question: str) -> Dict[str, Any]:
    """
    Deterministic Tier-3 SOC rulebook response grounded exclusively
    in the incident's confirmed numeric evidence.
    """
    feat = incident.get('features', {})
    label = incident.get('label', 'normal')
    score = incident.get('risk_score', 0)
    sev = incident.get('severity', 'Low')
    vector = incident.get('threat_vector', 'Unknown Flow')
    mitre = incident.get('mitre_technique', 'N/A')
    reasons = incident.get('reasons', [])
    engine = incident.get('engine', 'SentinelAI ML')
    
    syn = feat.get('syn_count', 0)
    packets = feat.get('packets', 0)
    ports = feat.get('unique_dst_ports', 0)
    failed = feat.get('failed_connections', 0)
    duration = feat.get('duration_ms', 0)
    bytes_val = feat.get('bytes', 0)

    evidence_summary = (
        f"- Flow Duration: {duration} ms\n"
        f"- Total Packets: {packets} | Byte Volume: {bytes_val} bytes\n"
        f"- TCP SYN Count: {syn} ({round((syn/max(packets, 1))*100, 1)}% of packets)\n"
        f"- Unique Destination Ports Contacted: {ports}\n"
        f"- Failed / Dropped Connections: {failed}"
    )

    if label == 'suspicious':
        # Specific mitigation playbooks based on vector
        if 'SYN Flood' in vector:
            mitigations = [
                "1. [Containment] Enable TCP SYN cookies on perimeter firewalls (`sysctl -w net.ipv4.tcp_syncookies=1`).",
                "2. [Rate Limiting] Implement iptables / pf rate-limiting on incoming SYN flags (e.g., `-m limit --limit 50/s --limit-burst 100`).",
                "3. [Upstream] Divert ingress traffic through cloud DDoS scrubbing (Cloudflare / AWS Shield / Arbor Networks).",
                "4. [Investigation] Capture pcap traces on the border interface to identify source IP distribution and spoofing signatures."
            ]
        elif 'Port Scan' in vector or 'Reconnaissance' in vector:
            mitigations = [
                "1. [Containment] Temporarily blacklist the source network segment at edge firewall / border ACL.",
                "2. [Deception] Verify that closed ports return DROP (silent discard) rather than TCP RST to slow down automated scanners.",
                "3. [Audit] Inspect egress firewall rules to ensure unneeded services on scanned ports are not exposed externally.",
                "4. [SIEM Correlation] Check threat intelligence feeds for correlated scanning activity across adjacent CIDR ranges."
            ]
        elif 'Brute Force' in vector or 'Credential' in vector:
            mitigations = [
                "1. [Access Control] Enforce fail2ban or dynamic IP throttling on authentication endpoints after 5 failed attempts.",
                "2. [Authentication] Require multi-factor authentication (MFA) and transition SSH to certificate-based keys.",
                "3. [Account Review] Audit authentication logs for affected target accounts to confirm no credential compromise occurred.",
                "4. [Network Isolation] Restrict administrative management ports (SSH/RDP) to approved VPN bastion subnets only."
            ]
        else:
            mitigations = [
                "1. [Inspection] Isolate flow endpoint and verify application-level transaction logs.",
                "2. [Firewall] Apply strict ingress bandwidth quotas per source IP.",
                "3. [Forensics] Preserve flow metadata and export PCAP for deep packet inspection."
            ]

        analysis = (
            f"### Incident Forensics & Root Cause\n"
            f"**Classification**: {label.upper()} | **Severity**: {sev} | **Risk Score**: {score}/100\n"
            f"**Threat Vector**: {vector}\n"
            f"**MITRE ATT&CK**: {mitre}\n"
            f"**Detection Engine**: {engine}\n\n"
            f"#### Confirmed Numeric Evidence:\n{evidence_summary}\n\n"
            f"#### Forensic Justification:\n"
            + "\n".join(f"- {r}" for r in reasons) + "\n\n"
            f"#### Tactical Mitigation Playbook:\n"
            + "\n".join(mitigations) + "\n\n"
            f"#### Responder Note:\n"
            f"This deterministic analysis is grounded strictly in the observed flow metrics without speculation."
        )
    else:
        analysis = (
            f"### Baseline Flow Evaluation\n"
            f"**Classification**: NORMAL | **Severity**: {sev} | **Risk Score**: {score}/100\n"
            f"**Flow Assessment**: The observed flow metrics fall comfortably within expected enterprise baseline parameters.\n\n"
            f"#### Observed Metrics:\n{evidence_summary}\n\n"
            f"#### Security Posture Note:\n"
            f"No volumetric anomalies, scanning patterns, or abnormal connection drops were detected. "
            f"Note: A 'Normal' rating indicates the flow did not trigger volumetric intrusion signatures; "
            f"defense-in-depth principles (segmentation, TLS inspection, identity verification) still apply."
        )

    return {
        'answer': analysis,
        'provider': 'deterministic-soc-engine (offline fallback)',
        'model': 'SOC Rulebook v2.4 (Grounded)',
        'disclaimer': 'Grounded strictly on provided network telemetry. No external LLM key supplied or network unavailable.'
    }

def analyze_with_llm(incident: Dict[str, Any], question: str) -> Optional[Dict[str, Any]]:
    """Attempts to analyze incident using Google Gemini LLM API via GEMINI_API_KEY."""
    api_key = os.getenv('GEMINI_API_KEY') or os.getenv('GOOGLE_API_KEY')
    if not api_key:
        return None

    prompt = f"""
You are SentinelAI Security Copilot, an elite Tier-3 Incident Response Analyst.
Analyze the following single network flow telemetry record.

CRITICAL RULES:
1. Ground your answer ONLY on the exact telemetry provided below.
2. DO NOT fabricate or hallucinate external IP addresses, domains, user accounts, or payloads not present in the record.
3. State the MITRE ATT&CK technique and explain how the telemetry metrics specifically justify it.
4. Provide prioritized, actionable defensive mitigation steps (Containment, Eradication, Monitoring).

INCIDENT RECORD:
- Incident ID: {incident.get('id')}
- Timestamp: {incident.get('timestamp')}
- Model Classification: {incident.get('label')} (Risk Score: {incident.get('risk_score')}/100, Severity: {incident.get('severity')})
- Probability: {incident.get('probability')}
- Threat Vector: {incident.get('threat_vector')}
- MITRE ATT&CK: {incident.get('mitre_technique')}
- Detection Reasons: {incident.get('reasons')}
- Flow Features: {json.dumps(incident.get('features', {}), indent=2)}

USER QUESTION: {question}
"""

    try:
        from google import genai
        client = genai.Client(api_key=api_key)
        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=prompt,
        )
        if response and response.text:
            return {
                'answer': response.text,
                'provider': 'gemini-llm',
                'model': 'gemini-2.5-flash',
                'disclaimer': 'AI-assisted analysis based strictly on submitted incident telemetry.'
            }
    except Exception as e:
        print(f"[SentinelAI Copilot] Gemini API call error: {e}")

    return None

def ask_copilot(incident: Dict[str, Any], question: str = "Explain this incident") -> Dict[str, Any]:
    # 1. Try real LLM if configured
    llm_result = analyze_with_llm(incident, question)
    if llm_result:
        return llm_result
        
    # 2. Seamlessly use deterministic evidence-grounded fallback
    return generate_fallback_analysis(incident, question)
