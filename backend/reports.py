"""
SentinelAI - Executive Cyber Incident Report Generator
Generates clean, structured, CISO-ready PDF incident reports using ReportLab Platypus.
"""

import io
from datetime import datetime, timezone
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    HRFlowable,
)

def generate_incident_pdf(incident: dict) -> io.BytesIO:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=letter,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )
    
    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=20,
        textColor=colors.HexColor('#0F172A'),
        spaceAfter=4
    )
    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        textColor=colors.HexColor('#64748B'),
        spaceAfter=15
    )
    h2_style = ParagraphStyle(
        'Heading2Custom',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=12,
        textColor=colors.HexColor('#1E293B'),
        spaceBefore=12,
        spaceAfter=6
    )
    body_style = ParagraphStyle(
        'BodyCustom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=colors.HexColor('#334155')
    )
    bold_style = ParagraphStyle(
        'BoldCustom',
        parent=body_style,
        fontName='Helvetica-Bold'
    )
    badge_style = ParagraphStyle(
        'Badge',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=11,
        alignment=1, # Center
        textColor=colors.white
    )

    story = []
    
    # Header Banner
    story.append(Paragraph("SENTINEL AI — CYBER THREAT INCIDENT REPORT", title_style))
    story.append(Paragraph(f"Generated at: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} | Security Operations Center", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#2563EB'), spaceAfter=15))
    
    # Executive Summary Card
    label = incident.get('label', 'normal').upper()
    sev = incident.get('severity', 'Low')
    score = incident.get('risk_score', 0)
    inc_id = incident.get('id', 'N/A')
    ts = incident.get('timestamp', 'N/A')
    vector = incident.get('threat_vector', 'Unknown')
    mitre = incident.get('mitre_technique', 'N/A')
    engine = incident.get('engine', 'Machine Learning')
    
    badge_color = colors.HexColor('#DC2626') if label == 'SUSPICIOUS' else colors.HexColor('#059669')
    
    summary_data = [
        [
            Paragraph(f"<b>INCIDENT ID:</b> {inc_id}", body_style),
            Paragraph(f"<b>STATUS:</b> {label}", badge_style)
        ],
        [
            Paragraph(f"<b>TIMESTAMP:</b> {ts}", body_style),
            Paragraph(f"<b>RISK SCORE:</b> {score} / 100 ({sev} Severity)", body_style)
        ],
        [
            Paragraph(f"<b>THREAT VECTOR:</b> {vector}", body_style),
            Paragraph(f"<b>DETECTION ENGINE:</b> {engine}", body_style)
        ],
        [
            Paragraph(f"<b>MITRE ATT&CK:</b> {mitre}", body_style),
            Paragraph(f"<b>CONFIDENCE:</b> {round(incident.get('confidence', 0.95)*100, 1)}%", body_style)
        ]
    ]
    
    summary_table = Table(summary_data, colWidths=[330, 200])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#F8FAFC')),
        ('BACKGROUND', (1, 0), (1, 0), badge_color),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#E2E8F0')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E2E8F0')),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ('RIGHTPADDING', (0, 0), (-1, -1), 10),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 14))

    # Observed Telemetry vs Baseline
    story.append(Paragraph("1. NETWORK FLOW TELEMETRY & BASELINE COMPARISON", h2_style))
    features = incident.get('features', {})
    
    telemetry_data = [
        ['Metric / Feature', 'Observed Value', 'Enterprise Baseline', 'Forensic Variance'],
        ['Flow Duration', f"{features.get('duration_ms', 0)} ms", "200 - 500 ms", "Nominal" if features.get('duration_ms', 0) < 1500 else "Anomalous"],
        ['Packet Count', f"{features.get('packets', 0)} pkts", "15 - 60 pkts", "Critical Volume" if features.get('packets', 0) > 200 else "Nominal"],
        ['Total Volume', f"{features.get('bytes', 0)} bytes", "2,000 - 25,000 bytes", "Elevated" if features.get('bytes', 0) > 50000 else "Nominal"],
        ['TCP SYN Flags', f"{features.get('syn_count', 0)} flags", "1 - 4 flags", "SYN Flood Alert" if features.get('syn_count', 0) >= 30 else "Nominal"],
        ['Unique Dst Ports', f"{features.get('unique_dst_ports', 0)} ports", "1 - 2 ports", "Port Scan Alert" if features.get('unique_dst_ports', 0) >= 10 else "Nominal"],
        ['Failed Connections', f"{features.get('failed_connections', 0)} drops", "0 - 2 drops", "Brute Force Alert" if features.get('failed_connections', 0) >= 15 else "Nominal"],
    ]
    
    tel_table = Table(telemetry_data, colWidths=[150, 120, 130, 130])
    tel_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1E293B')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 8.5),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#F8FAFC')]),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
    ]))
    story.append(tel_table)
    story.append(Spacer(1, 14))

    # Forensic Findings
    story.append(Paragraph("2. DETECTION JUSTIFICATION & ROOT CAUSE", h2_style))
    reasons = incident.get('reasons', [])
    for r in reasons:
        story.append(Paragraph(f"• <b>Trigger</b>: {r}", body_style))
        story.append(Spacer(1, 3))
    story.append(Spacer(1, 10))

    # Defensive Mitigation Playbook
    story.append(Paragraph("3. RECOMMENDED DEFENSIVE MITIGATION ACTIONS", h2_style))
    if label == 'SUSPICIOUS':
        if 'SYN' in vector:
            mitigations = [
                "<b>[Perimeter]</b> Enable TCP SYN flood protection and SYN cookies (`net.ipv4.tcp_syncookies = 1`).",
                "<b>[Rate Limiting]</b> Throttle inbound TCP connections on border firewalls to max 50 SYN/sec per source IP.",
                "<b>[Upstream]</b> Activate cloud DDoS mitigation proxy / IP scrubbers.",
                "<b>[Auditing]</b> Inspect edge network logs to track originating Autonomous System Numbers (ASNs)."
            ]
        elif 'Port Scan' in vector:
            mitigations = [
                "<b>[Firewall]</b> Drop non-solicited ingress TCP packets without transmitting RST packets (silent DROP).",
                "<b>[Access Control]</b> Implement dynamic firewall blacklisting (e.g. fail2ban / pf) for IPs exceeding 10 port probes.",
                "<b>[Hardening]</b> Verify that management interfaces (SSH, RDP, Web Admin) are bound exclusively to VPN subnets.",
                "<b>[SIEM Rule]</b> Tag correlated network discovery events from this source across the last 24 hours."
            ]
        elif 'Brute Force' in vector:
            mitigations = [
                "<b>[Authentication]</b> Enforce progressive exponential backoff and IP lockout after 5 consecutive failures.",
                "<b>[Credential Security]</b> Mandate hardware MFA tokens or certificate-based SSH keys across all endpoints.",
                "<b>[Review]</b> Immediately audit all authentication successes from this source IP to ensure no accounts were breached.",
                "<b>[Isolation]</b> Temporarily quarantine the destination server if anomalous outbound sessions are detected."
            ]
        else:
            mitigations = [
                "<b>[Containment]</b> Apply ingress bandwidth caps and inspect application-layer payload logs.",
                "<b>[Monitoring]</b> Elevate SIEM log ingestion level for the affected destination host."
            ]
    else:
        mitigations = [
            "<b>[Baseline Maintenance]</b> Record flow statistics to periodically retrain the anomaly baseline model.",
            "<b>[Continuous Inspection]</b> Maintain existing deep packet inspection and zero-trust microsegmentation controls."
        ]
        
    for m in mitigations:
        story.append(Paragraph(f"• {m}", body_style))
        story.append(Spacer(1, 3))
    story.append(Spacer(1, 15))

    # SOC Responder Sign-Off Box
    signoff_data = [
        [
            Paragraph("<b>SOC Analyst Sign-off:</b><br/>Verified by SentinelAI IR Automation", body_style),
            Paragraph("<b>Action Status:</b><br/>[X] Auto-Classified &nbsp;&nbsp; [ ] Manually Remediated &nbsp;&nbsp; [ ] Closed", body_style)
        ]
    ]
    signoff_table = Table(signoff_data, colWidths=[265, 265])
    signoff_table.setStyle(TableStyle([
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#94A3B8')),
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#F1F5F9')),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ('RIGHTPADDING', (0, 0), (-1, -1), 10),
    ]))
    story.append(signoff_table)
    
    doc.build(story)
    buf.seek(0)
    return buf
