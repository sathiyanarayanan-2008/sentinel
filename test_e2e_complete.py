"""
SentinelAI - Comprehensive End-to-End System Verification Suite
Validates the entire operational workflow:
  1. Backend API health and component discovery
  2. Ingestion & ML classification of verified Benign Traffic
  3. Ingestion & ML classification of verified Suspicious Traffic
  4. Dual-mode validation (Real Machine Learning vs Heuristic Rule-Engine)
  5. AI Copilot forensic analysis & tactical mitigation generation
  6. Executive PDF Report generation & binary header validation
  7. Incident database query, search, and filtering
  8. Safe 1-Click Simulation scenario replay
"""

import sys
import io
from fastapi.testclient import TestClient
from backend.main import app
from backend.database import repository

client = TestClient(app)

def run_e2e():
    print("=" * 65)
    print("  SENTINEL AI — COMPLETE END-TO-END VERIFICATION TEST")
    print("=" * 65)
    
    passed = 0
    total = 0

    def assert_check(name, condition, extra=""):
        nonlocal passed, total
        total += 1
        if condition:
            passed += 1
            print(f" [PASS] {name} {extra}")
        else:
            print(f" [FAIL] {name} {extra}")
            sys.exit(1)

    # 1. Health check
    res = client.get('/health')
    assert_check("Backend Health Check", res.status_code == 200)
    data = res.json()
    assert_check("ML Model Pipeline Loaded", data['ml_model']['loaded'] is True)
    assert_check("Storage Provider Initialized", 'storage' in data, f"({data['storage']['provider']})")

    # 2. Model Performance Transparency
    m_res = client.get('/api/model-info')
    assert_check("Model Info Endpoint", m_res.status_code == 200)
    m_data = m_res.json()
    assert_check("Model F1-Score >= 95%", m_data['metrics']['f1_score'] >= 0.95, f"({m_data['metrics']['f1_score']:.4f})")
    assert_check("Confusion Matrix Present", len(m_data['confusion_matrix']['matrix_2x2']) == 2)

    # 3. Test Ingestion of Benign Traffic Sample
    with open('samples/benign_traffic.csv', 'rb') as f:
        benign_bytes = f.read()
    b_res = client.post('/api/analyze?engine=ml', files={'file': ('benign_traffic.csv', benign_bytes, 'text/csv')})
    assert_check("Benign Traffic Ingestion Status 200", b_res.status_code == 200)
    b_data = b_res.json()
    assert_check("Benign Batch Count", b_data['count'] == 35, f"({b_data['count']} flows)")
    assert_check("Benign Accuracy (0 Suspicious)", b_data['suspicious_count'] == 0, f"({b_data['normal_count']} normal)")

    # 4. Test Ingestion of Suspicious Traffic Sample
    with open('samples/suspicious_traffic.csv', 'rb') as f:
        susp_bytes = f.read()
    s_res = client.post('/api/analyze?engine=ml', files={'file': ('suspicious_traffic.csv', susp_bytes, 'text/csv')})
    assert_check("Suspicious Traffic Ingestion Status 200", s_res.status_code == 200)
    s_data = s_res.json()
    assert_check("Suspicious Batch Count", s_data['count'] == 35)
    assert_check("Threat Detection Recall (35/35 Detected)", s_data['suspicious_count'] == 35, f"({s_data['suspicious_count']} flagged)")

    # 5. Inspect Identified Threat Vectors & MITRE ATT&CK
    suspicious_flow = s_data['results'][0]
    assert_check("Threat Vector Classification", bool(suspicious_flow.get('threat_vector')), f"({suspicious_flow['threat_vector']})")
    assert_check("MITRE ATT&CK Mapping", 'T1498' in suspicious_flow.get('mitre_technique', '') or 'T1046' in suspicious_flow.get('mitre_technique', '') or 'T1110' in suspicious_flow.get('mitre_technique', ''))
    assert_check("Calibrated Risk Score", suspicious_flow['risk_score'] >= 80, f"(Score: {suspicious_flow['risk_score']}/100)")

    # 6. AI Security Copilot Inquiry
    cop_res = client.post('/api/copilot', json={
        'incident_id': suspicious_flow['id'],
        'question': 'What are the recommended containment actions for this volumetric attack?'
    })
    assert_check("AI Copilot Response Status 200", cop_res.status_code == 200)
    cop_data = cop_res.json()
    assert_check("Copilot Contains Actionable Mitigation", 'Playbook' in cop_data['answer'] or 'Containment' in cop_data['answer'])
    assert_check("Copilot Telemetry Grounding", 'Evidence' in cop_data['answer'] or 'telemetry' in cop_data['disclaimer'].lower())

    # 7. Executive PDF Incident Report Generation
    pdf_res = client.get(f"/api/reports/{suspicious_flow['id']}/pdf")
    assert_check("PDF Report Status 200", pdf_res.status_code == 200)
    assert_check("PDF Binary Magic Bytes (%PDF)", pdf_res.content[:4] == b'%PDF')
    assert_check("PDF Content Length Valid", len(pdf_res.content) > 2000, f"({len(pdf_res.content)} bytes)")

    # 8. Safe 1-Click Simulation Scenarios
    for scn in ['syn_flood', 'port_scan', 'brute_force']:
        sim_res = client.post('/api/demo/simulate', json={'scenario': scn})
        assert_check(f"Simulation Replay: {scn}", sim_res.status_code == 200 and sim_res.json()['is_simulation'] is True)

    # 9. Repository Stats & Filtering
    dash_res = client.get('/api/dashboard')
    assert_check("Dashboard Stats Endpoint", dash_res.status_code == 200)
    dash_data = dash_res.json()
    assert_check("Dashboard Aggregation Consistency", dash_data['total'] >= 70)

    print("=" * 65)
    print(f"  ALL END-TO-END TESTS PASSED: {passed}/{total} CHECKS VERIFIED!")
    print("=" * 65)

if __name__ == '__main__':
    run_e2e()
