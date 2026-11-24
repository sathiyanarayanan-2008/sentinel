"""
SentinelAI - Enterprise Cyber Threat Detection & Incident Response API
FastAPI backend powering Real ML intrusion detection, AI Security Copilot,
MongoDB Atlas persistence, and Executive PDF reporting.
"""

import csv
import io
import math
import os
import uuid
from datetime import datetime, timezone
from typing import Optional, List

from fastapi import FastAPI, UploadFile, File, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from .ml import FEATURES, classify, get_model
from .database import repository
from .copilot import ask_copilot
from .reports import generate_incident_pdf

app = FastAPI(
    title='SentinelAI Threat Intelligence Platform',
    version='1.0.0',
    description='AI-Powered Cyber Threat Detection, Incident Response & Autonomous SOC Copilot'
)

# CORS Configuration - Allow all origins for seamless Vercel / Cloud deployment
app.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],
    allow_credentials=False,
    allow_methods=['*'],
    allow_headers=['*'],
)

MAX_BYTES = 2 * 1024 * 1024 # 2 MB limit

@app.get('/')
def root():
    return {
        'service': 'SentinelAI Threat Intelligence Engine',
        'status': 'online',
        'version': '1.0.0',
        'health_check': '/health',
        'api_docs': '/docs'
    }

@app.get('/health')
def health():
    _, metrics = get_model()
    storage_info = repository.get_status()
    has_gemini = bool(os.getenv('GEMINI_API_KEY') or os.getenv('GOOGLE_API_KEY'))
    
    return {
        'status': 'ok',
        'service': 'SentinelAI Threat Intelligence Engine',
        'version': '1.0.0',
        'mode': 'real-ml-production',
        'ml_model': {
            'loaded': metrics is not None,
            'algorithm': metrics.get('algorithm') if metrics else 'Rule-based fallback',
            'f1_score': metrics.get('metrics', {}).get('f1_score') if metrics else None,
            'accuracy': metrics.get('metrics', {}).get('accuracy') if metrics else None
        },
        'storage': storage_info,
        'copilot': {
            'llm_provider': 'gemini-llm' if has_gemini else 'deterministic-soc-engine (fallback)',
            'api_key_configured': has_gemini
        }
    }

@app.get('/api/model-info')
def model_info():
    """Returns the trained ML model performance metrics, dataset info, and confusion matrix."""
    _, metrics = get_model()
    if not metrics:
        raise HTTPException(503, "ML model metrics not available. Run train_model.py first.")
    return metrics

@app.get('/api/dashboard')
def dashboard():
    stats = repository.get_dashboard_stats()
    return stats

@app.post('/api/analyze')
async def analyze(
    file: UploadFile = File(...),
    engine: Optional[str] = Query('ml', description="Inference engine: 'ml' or 'rule-based'")
):
    if not file.filename or not file.filename.lower().endswith('.csv'):
        raise HTTPException(400, 'Invalid file type. Please upload a .csv file.')
        
    raw = await file.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise HTTPException(413, 'File size exceeds 2 MB limit.')
        
    try:
        decoded = raw.decode('utf-8-sig')
    except UnicodeDecodeError:
        raise HTTPException(400, 'CSV encoding must be valid UTF-8.')

    try:
        reader = csv.DictReader(io.StringIO(decoded))
        if not reader.fieldnames:
            raise HTTPException(400, 'CSV file has no header row.')
            
        missing = set(FEATURES) - set(reader.fieldnames)
        if missing:
            raise HTTPException(
                400,
                f"Missing required feature columns: {', '.join(sorted(missing))}. "
                f"Required schema: {', '.join(FEATURES)}"
            )

        new_incidents = []
        now_iso = datetime.now(timezone.utc).isoformat()
        
        for n, row in enumerate(reader, 1):
            if n > 500:
                raise HTTPException(400, 'Maximum limit is 500 rows per upload.')
                
            clean_feats = {}
            for k in FEATURES:
                val_str = row.get(k)
                if val_str is None or val_str.strip() == '':
                    raise HTTPException(400, f"Missing value for '{k}' on row {n}")
                try:
                    val_float = float(val_str)
                except (ValueError, TypeError):
                    raise HTTPException(400, f"Invalid non-numeric value for '{k}' on row {n}: '{val_str}'")
                    
                if not math.isfinite(val_float):
                    raise HTTPException(400, f"Non-finite value for '{k}' on row {n}")
                if val_float < 0:
                    raise HTTPException(400, f"Negative value not allowed for '{k}' on row {n}: {val_float}")
                    
                clean_feats[k] = val_float
                
            result = classify(clean_feats, engine=engine)
            incident = {
                'id': str(uuid.uuid4()),
                'timestamp': now_iso,
                'row': n,
                'features': clean_feats,
                'source': f"upload:{file.filename}",
                **result
            }
            new_incidents.append(incident)

        if not new_incidents:
            raise HTTPException(400, 'CSV contains no data rows.')

        # Persist to repository (MongoDB or local persistent JSON)
        repository.save_incidents(new_incidents)

        return {
            'status': 'success',
            'engine_used': engine,
            'count': len(new_incidents),
            'suspicious_count': sum(1 for i in new_incidents if i['label'] == 'suspicious'),
            'normal_count': sum(1 for i in new_incidents if i['label'] == 'normal'),
            'results': new_incidents
        }

    except csv.Error as e:
        raise HTTPException(400, f"Malformed CSV structure: {e}")

@app.get('/api/incidents')
def get_incidents(
    label: Optional[str] = Query(None, description="Filter by label ('suspicious', 'normal', 'all')"),
    severity: Optional[str] = Query(None, description="Filter by severity ('Critical', 'High', 'Medium', 'Low')"),
    search: Optional[str] = Query(None, description="Search by ID or threat vector"),
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0)
):
    return repository.list_incidents(
        label=label,
        severity=severity,
        search=search,
        limit=limit,
        offset=offset
    )

@app.get('/api/incidents/{incident_id}')
def get_incident(incident_id: str):
    inc = repository.get_incident(incident_id)
    if not inc:
        raise HTTPException(404, f"Incident with ID '{incident_id}' not found.")
    return inc

@app.delete('/api/incidents')
def clear_all_incidents():
    """Clears all stored incidents (useful for demo state resets)."""
    repository.clear_all()
    return {'status': 'success', 'message': 'All incidents have been cleared.'}

class CopilotQuestion(BaseModel):
    incident_id: str = Field(..., description="Target incident UUID")
    question: str = Field('Explain this incident and suggest mitigation steps', description="Investigative query")

@app.post('/api/copilot')
def copilot_endpoint(payload: CopilotQuestion):
    inc = repository.get_incident(payload.incident_id)
    if not inc:
        raise HTTPException(404, f"Incident with ID '{payload.incident_id}' not found.")
    return ask_copilot(inc, question=payload.question)

@app.get('/api/reports/{incident_id}/pdf')
def download_pdf(incident_id: str):
    inc = repository.get_incident(incident_id)
    if not inc:
        raise HTTPException(404, f"Incident with ID '{incident_id}' not found.")
        
    pdf_buffer = generate_incident_pdf(inc)
    short_id = incident_id[:8]
    filename = f"SentinelAI-Report-{short_id}.pdf"
    
    return StreamingResponse(
        pdf_buffer,
        media_type='application/pdf',
        headers={
            'Content-Disposition': f'attachment; filename="{filename}"'
        }
    )

class SimulationRequest(BaseModel):
    scenario: str = Field(..., description="Scenario type: syn_flood, port_scan, brute_force, or benign")

@app.post('/api/demo/simulate')
def simulate_attack(payload: SimulationRequest):
    """
    Safe offline demonstration scenario simulator.
    Ingests calibrated synthetic flows without sending real network packets.
    """
    scenarios = {
        'syn_flood': {
            'duration_ms': 420.0,
            'packets': 780.0,
            'bytes': 72000.0,
            'syn_count': 195.0,
            'unique_dst_ports': 2.0,
            'failed_connections': 8.0,
            'desc': 'Simulated SYN Flood volumetric attack targeting web tier'
        },
        'port_scan': {
            'duration_ms': 1250.0,
            'packets': 65.0,
            'bytes': 3800.0,
            'syn_count': 58.0,
            'unique_dst_ports': 55.0,
            'failed_connections': 48.0,
            'desc': 'Simulated Nmap SYN stealth scan targeting internal subnets'
        },
        'brute_force': {
            'duration_ms': 850.0,
            'packets': 160.0,
            'bytes': 14200.0,
            'syn_count': 18.0,
            'unique_dst_ports': 3.0,
            'failed_connections': 75.0,
            'desc': 'Simulated SSH credential stuffing flood with high drop rate'
        },
        'benign': {
            'duration_ms': 320.0,
            'packets': 42.0,
            'bytes': 11800.0,
            'syn_count': 2.0,
            'unique_dst_ports': 1.0,
            'failed_connections': 0.0,
            'desc': 'Simulated standard HTTPS API transaction'
        }
    }
    
    selected = scenarios.get(payload.scenario.lower())
    if not selected:
        raise HTTPException(400, f"Unknown scenario: '{payload.scenario}'. Available: {list(scenarios.keys())}")
        
    flow_features = {k: selected[k] for k in FEATURES}
    classified = classify(flow_features, engine='ml')
    
    simulated_incident = {
        'id': str(uuid.uuid4()),
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'row': 1,
        'features': flow_features,
        'source': f"[SIMULATED - SAFE REPLAY] {selected['desc']}",
        'is_simulation': True,
        **classified
    }
    
    repository.save_incident(simulated_incident)
    return simulated_incident
