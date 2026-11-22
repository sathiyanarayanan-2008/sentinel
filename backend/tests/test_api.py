import io
import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend.database import repository

client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_teardown():
    # Clean store for isolated test execution
    repository.clear_all()
    yield
    repository.clear_all()

def test_health():
    res = client.get('/health')
    assert res.status_code == 200
    data = res.json()
    assert data['status'] == 'ok'
    assert data['mode'] == 'real-ml-production'
    assert data['ml_model']['loaded'] is True
    assert 'storage' in data

def test_model_info():
    res = client.get('/api/model-info')
    assert res.status_code == 200
    data = res.json()
    assert 'algorithm' in data
    assert 'metrics' in data
    assert data['metrics']['f1_score'] >= 0.95
    assert 'confusion_matrix' in data
    assert 'feature_importances' in data

def test_ml_upload_and_pdf_generation():
    csv_content = (
        b"duration_ms,packets,bytes,syn_count,unique_dst_ports,failed_connections\n"
        b"300,595,65000,109,2,4\n"
        b"320,42,11250,2,1,0\n"
    )
    res = client.post(
        '/api/analyze?engine=ml',
        files={'file': ('traffic.csv', csv_content, 'text/csv')}
    )
    assert res.status_code == 200
    data = res.json()
    assert data['status'] == 'success'
    assert data['count'] == 2
    assert data['suspicious_count'] == 1
    assert data['normal_count'] == 1
    
    suspicious_inc = [x for x in data['results'] if x['label'] == 'suspicious'][0]
    assert suspicious_inc['is_ml'] is True
    assert 'risk_score' in suspicious_inc
    assert suspicious_inc['risk_score'] > 50
    assert 'threat_vector' in suspicious_inc
    
    # Test PDF generation for this incident
    pdf_res = client.get(f"/api/reports/{suspicious_inc['id']}/pdf")
    assert pdf_res.status_code == 200
    assert pdf_res.headers['content-type'] == 'application/pdf'
    assert pdf_res.content[:4] == b'%PDF'

def test_copilot_investigation():
    # Create incident first via simulation
    sim_res = client.post('/api/demo/simulate', json={'scenario': 'syn_flood'})
    assert sim_res.status_code == 200
    incident_id = sim_res.json()['id']
    
    # Query copilot
    cop_res = client.post('/api/copilot', json={
        'incident_id': incident_id,
        'question': 'How should the SOC contain this attack?'
    })
    assert cop_res.status_code == 200
    cop_data = cop_res.json()
    assert 'answer' in cop_data
    assert len(cop_data['answer']) > 50
    assert 'provider' in cop_data
    assert 'disclaimer' in cop_data

def test_bad_uploads():
    # Missing required columns
    bad_headers = b"duration_ms,packets\n100,50\n"
    r1 = client.post('/api/analyze', files={'file': ('bad.csv', bad_headers, 'text/csv')})
    assert r1.status_code == 400
    assert 'Missing required feature columns' in r1.json()['detail']

    # Non-numeric value
    bad_num = b"duration_ms,packets,bytes,syn_count,unique_dst_ports,failed_connections\n100,abc,1000,1,1,0\n"
    r2 = client.post('/api/analyze', files={'file': ('bad.csv', bad_num, 'text/csv')})
    assert r2.status_code == 400
    assert 'Invalid non-numeric value' in r2.json()['detail']

    # Negative value
    neg_val = b"duration_ms,packets,bytes,syn_count,unique_dst_ports,failed_connections\n100,50,1000,-5,1,0\n"
    r3 = client.post('/api/analyze', files={'file': ('bad.csv', neg_val, 'text/csv')})
    assert r3.status_code == 400
    assert 'Negative value not allowed' in r3.json()['detail']

def test_simulation_scenarios():
    for scenario in ['syn_flood', 'port_scan', 'brute_force', 'benign']:
        res = client.post('/api/demo/simulate', json={'scenario': scenario})
        assert res.status_code == 200
        data = res.json()
        assert data['is_simulation'] is True
        if scenario != 'benign':
            assert data['label'] == 'suspicious'
        else:
            assert data['label'] == 'normal'

def test_dashboard_and_filtering():
    client.post('/api/demo/simulate', json={'scenario': 'syn_flood'})
    client.post('/api/demo/simulate', json={'scenario': 'benign'})
    
    dash = client.get('/api/dashboard').json()
    assert dash['total'] == 2
    assert dash['suspicious'] == 1
    assert dash['normal'] == 1
    
    # Filter by suspicious
    incidents = client.get('/api/incidents?label=suspicious').json()
    assert len(incidents) == 1
    assert incidents[0]['label'] == 'suspicious'
