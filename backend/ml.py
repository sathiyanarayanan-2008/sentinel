"""
SentinelAI - Dual Inference Machine Learning & Rule-Based Threat Engine
Features:
  - duration_ms, packets, bytes, syn_count, unique_dst_ports, failed_connections
"""

import json
import os
import math
import joblib
import numpy as np
import pandas as pd

FEATURES = ['duration_ms', 'packets', 'bytes', 'syn_count', 'unique_dst_ports', 'failed_connections']

# Baseline averages for normal enterprise traffic
NORMAL_BASELINE = {
    'duration_ms': 350.0,
    'packets': 45.0,
    'bytes': 11250.0,
    'syn_count': 2.0,
    'unique_dst_ports': 1.0,
    'failed_connections': 0.0
}

MODEL_PATH = os.path.join(os.path.dirname(__file__), 'sentinel_model.joblib')
METRICS_PATH = os.path.join(os.path.dirname(__file__), 'model_metrics.json')

_model_pipeline = None
_model_metrics = None

def get_model():
    global _model_pipeline, _model_metrics
    if _model_pipeline is None and os.path.exists(MODEL_PATH):
        try:
            _model_pipeline = joblib.load(MODEL_PATH)
        except Exception as e:
            print(f"[SentinelAI ML] Warning: could not load model pipeline: {e}")
            _model_pipeline = None
            
    if _model_metrics is None and os.path.exists(METRICS_PATH):
        try:
            with open(METRICS_PATH, 'r', encoding='utf-8') as f:
                _model_metrics = json.load(f)
        except Exception as e:
            print(f"[SentinelAI ML] Warning: could not load metrics: {e}")
            _model_metrics = None
            
    return _model_pipeline, _model_metrics

def identify_threat_vector(row_dict: dict) -> tuple[str, str, str]:
    """
    Identifies the probable threat vector, severity, and MITRE ATT&CK technique
    based on feature anomaly characteristics.
    """
    syn = row_dict['syn_count']
    packets = row_dict['packets']
    ports = row_dict['unique_dst_ports']
    failed = row_dict['failed_connections']
    bytes_val = row_dict['bytes']
    
    # 1. Volumetric SYN Flood
    if syn >= 50 or (packets > 100 and (syn / max(packets, 1)) > 0.4):
        return (
            "Volumetric DDoS (TCP SYN Flood)",
            "Critical",
            "T1498.001 - Network Denial of Service: Direct Network Flood"
        )
    # 2. Port Reconnaissance / Network Sweep
    elif ports >= 15 or (ports > 8 and failed > 10):
        return (
            "Network Reconnaissance / Port Scan",
            "High",
            "T1046 - Network Service Discovery"
        )
    # 3. Credential Stuffing / Brute Force
    elif failed >= 20:
        return (
            "Authentication Brute Force / Credential Exhaustion",
            "High",
            "T1110 - Brute Force"
        )
    # 4. High Volume Anomalous Burst
    elif packets >= 800:
        return (
            "Anomalous Traffic Spike / Buffer Stress",
            "Medium",
            "T1499 - Endpoint Denial of Service"
        )
    # 5. Low-and-Slow Probe
    elif row_dict['duration_ms'] > 3000 and failed >= 5:
        return (
            "Low-and-Slow Application Probe",
            "Medium",
            "T1059 - Command and Scripting Interpreter"
        )
    else:
        return (
            "Benign Enterprise Flow",
            "Low",
            "N/A - Legitimate Baseline Activity"
        )

def explain_features(row_dict: dict) -> list[str]:
    """Generates human-readable forensic reasons based on deviations from baseline."""
    reasons = []
    syn = row_dict['syn_count']
    packets = row_dict['packets']
    ports = row_dict['unique_dst_ports']
    failed = row_dict['failed_connections']
    duration = row_dict['duration_ms']
    bytes_val = row_dict['bytes']
    
    if syn >= 70 and packets >= 100:
        reasons.append(f"Elevated TCP SYN rate ({int(syn)} SYNs in {int(packets)} packets) indicating SYN flood handshake saturation")
    elif syn >= 30:
        reasons.append(f"Unusually high SYN flag count ({int(syn)} SYNs)")
        
    if ports >= 18:
        reasons.append(f"Horizontal/Vertical port scan behavior: {int(ports)} unique destination ports targeted in single window")
    elif ports >= 8:
        reasons.append(f"Multi-port probing: {int(ports)} distinct destination ports contacted")
        
    if failed >= 30:
        reasons.append(f"Severe connection reset rate ({int(failed)} failed/dropped handshakes), indicative of credential stuffing or port rejection")
    elif failed >= 10:
        reasons.append(f"Elevated failed connections ({int(failed)} drops)")
        
    if packets >= 900:
        reasons.append(f"Extreme volumetric packet burst ({int(packets)} packets in {int(duration)} ms)")
    elif duration > 0 and (packets / (duration / 1000.0)) > 500:
        reasons.append(f"High packet velocity ({round(packets / (duration / 1000.0), 1)} pkts/sec)")

    if not reasons:
        reasons.append("Flow parameters align with standard enterprise communication profiles.")
        
    return reasons

def classify(row: dict, engine: str = 'ml') -> dict:
    """
    Classifies a single network flow record using either the real trained ML pipeline
    or heuristic rule-based detection.
    """
    clean_row = {k: float(row[k]) for k in FEATURES}
    model, _ = get_model()
    
    threat_vector, default_severity, mitre_technique = identify_threat_vector(clean_row)
    reasons = explain_features(clean_row)
    
    # 1. Real ML Model Detection
    if engine == 'ml' and model is not None:
        try:
            X = pd.DataFrame([clean_row])[FEATURES]
            pred = int(model.predict(X)[0])
            probs = model.predict_proba(X)[0]
            ml_prob = float(probs[1]) if len(probs) > 1 else float(pred)
            
            # Anomaly indicator check (Port scan, SYN flood, Brute force thresholds)
            has_intrusion_indicators = (
                clean_row['unique_dst_ports'] >= 15 or
                clean_row['failed_connections'] >= 25 or
                clean_row['syn_count'] >= 50 or
                clean_row['packets'] >= 800
            )
            
            is_suspicious = (pred == 1) or (ml_prob >= 0.50) or has_intrusion_indicators
            label = 'suspicious' if is_suspicious else 'normal'
            
            calibrated_prob = max(ml_prob, 0.85) if (is_suspicious and ml_prob < 0.50) else ml_prob
            risk_score = int(round(calibrated_prob * 100))
            
            # Map severity
            if label == 'normal':
                severity = 'Low' if risk_score > 25 else 'Info'
                threat_vector = "Benign Enterprise Flow"
                mitre_technique = "N/A - Legitimate Baseline Activity"
            else:
                if risk_score >= 85:
                    severity = 'Critical'
                elif risk_score >= 65:
                    severity = 'High'
                else:
                    severity = 'Medium'
                    
            return {
                'label': label,
                'risk_score': max(5, risk_score),
                'probability': round(calibrated_prob, 4),
                'confidence': round(max(probs), 4),
                'severity': severity,
                'threat_vector': threat_vector,
                'mitre_technique': mitre_technique,
                'reasons': reasons,
                'engine': 'Machine Learning (Random Forest Pipeline)',
                'is_ml': True
            }
        except Exception as e:
            print(f"[SentinelAI ML] Inference error, falling back to rule-based: {e}")

    # 2. Rule-Based / Heuristic Fallback
    triggered = []
    if clean_row['syn_count'] >= 70 and clean_row['packets'] >= 100:
        triggered.append('High SYN count and packet volume')
    if clean_row['unique_dst_ports'] >= 18:
        triggered.append('Many destination ports contacted')
    if clean_row['failed_connections'] >= 30:
        triggered.append('Elevated failed connections')
    if clean_row['packets'] >= 900:
        triggered.append('Unusually high packet volume')
        
    label = 'suspicious' if triggered else 'normal'
    score = min(95, 10 + 30 * len(triggered))
    severity = 'High' if len(triggered) >= 2 else ('Medium' if triggered else 'Low')
    
    return {
        'label': label,
        'risk_score': score,
        'probability': round(score / 100.0, 2),
        'confidence': 0.85 if triggered else 0.90,
        'severity': severity,
        'threat_vector': threat_vector if label == 'suspicious' else "Benign Enterprise Flow",
        'mitre_technique': mitre_technique if label == 'suspicious' else "N/A - Legitimate Baseline Activity",
        'reasons': reasons if triggered else ['No threshold exceeded'],
        'engine': 'Heuristic Rules Engine (Fallback)',
        'is_ml': False
    }
