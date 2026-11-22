"""
SentinelAI - Network Threat Detection Model Training Pipeline
Dataset Architecture: Network Flow Intrusion Benchmarking (inspired by CIC-IDS2017 / NSL-KDD)
Feature Schema:
  - duration_ms: Flow duration in milliseconds
  - packets: Total packets in flow
  - bytes: Total volume of bytes transferred
  - syn_count: Number of TCP SYN flags observed
  - unique_dst_ports: Count of unique destination ports targeted
  - failed_connections: Number of failed or reset connections in session
"""

import json
import os
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

FEATURES = ['duration_ms', 'packets', 'bytes', 'syn_count', 'unique_dst_ports', 'failed_connections']

def generate_intrusion_dataset(n_samples: int = 8000, random_state: int = 42) -> pd.DataFrame:
    rng = np.random.RandomState(random_state)
    
    n_normal = int(n_samples * 0.60)
    n_dos = int(n_samples * 0.15)
    n_scan = int(n_samples * 0.13)
    n_brute = n_samples - n_normal - n_dos - n_scan

    # 1. Benign Traffic
    # Legitimate enterprise flows: 1-3 ports, low SYN ratio (~2-5%), minimal connection failures
    duration_normal = rng.exponential(scale=350, size=n_normal) + 20
    packets_normal = rng.poisson(lam=45, size=n_normal) + 5
    bytes_normal = packets_normal * rng.normal(loc=260, scale=70, size=n_normal).clip(min=50)
    syn_normal = rng.binomial(n=packets_normal.astype(int), p=0.03).clip(max=4)
    dst_ports_normal = rng.choice([1, 2, 3], size=n_normal, p=[0.80, 0.16, 0.04])
    failed_normal = rng.binomial(n=4, p=0.03, size=n_normal)
    
    df_normal = pd.DataFrame({
        'duration_ms': np.round(duration_normal, 1),
        'packets': packets_normal.astype(int),
        'bytes': np.round(bytes_normal).astype(int),
        'syn_count': syn_normal.astype(int),
        'unique_dst_ports': dst_ports_normal.astype(int),
        'failed_connections': failed_normal.astype(int),
        'label': 0,
        'attack_type': 'benign'
    })

    # 2. Volumetric / SYN Flood DDoS
    # High packet rate, extreme SYN volume, fixed single/dual port targets
    duration_dos = rng.uniform(100, 1500, size=n_dos)
    packets_dos = rng.normal(loc=700, scale=180, size=n_dos).clip(min=150)
    bytes_dos = packets_dos * rng.uniform(45, 95, size=n_dos)
    syn_dos = (packets_dos * rng.uniform(0.70, 0.98, size=n_dos)).clip(min=80)
    dst_ports_dos = rng.choice([1, 2], size=n_dos, p=[0.90, 0.10])
    failed_dos = rng.normal(loc=14, scale=6, size=n_dos).clip(min=0)
    
    df_dos = pd.DataFrame({
        'duration_ms': np.round(duration_dos, 1),
        'packets': np.round(packets_dos).astype(int),
        'bytes': np.round(bytes_dos).astype(int),
        'syn_count': np.round(syn_dos).astype(int),
        'unique_dst_ports': dst_ports_dos.astype(int),
        'failed_connections': np.round(failed_dos).astype(int),
        'label': 1,
        'attack_type': 'dos_syn_flood'
    })

    # 3. Port Scanning / Reconnaissance (horizontal & vertical sweep)
    # Probing many ports (15 to 150), mixed scan profiles (SYN scan, connect scan, UDP probe), high failure rate
    duration_scan = rng.uniform(400, 3000, size=n_scan)
    dst_ports_scan = rng.uniform(15, 120, size=n_scan)
    packets_scan = dst_ports_scan * rng.uniform(1.0, 2.2, size=n_scan)
    bytes_scan = packets_scan * rng.uniform(40, 80, size=n_scan)
    # Real-world scanners exhibit varying SYN rates depending on TCP vs UDP vs connect scans:
    is_syn_sweep = rng.uniform(0, 1, size=n_scan) > 0.30
    syn_scan = np.where(is_syn_sweep, packets_scan * rng.uniform(0.6, 1.0, size=n_scan), rng.uniform(3, 10, size=n_scan))
    failed_scan = (dst_ports_scan * rng.uniform(0.5, 0.95, size=n_scan)).clip(min=12)
    
    df_scan = pd.DataFrame({
        'duration_ms': np.round(duration_scan, 1),
        'packets': np.round(packets_scan).astype(int),
        'bytes': np.round(bytes_scan).astype(int),
        'syn_count': np.round(syn_scan).astype(int),
        'unique_dst_ports': np.round(dst_ports_scan).astype(int),
        'failed_connections': np.round(failed_scan).astype(int),
        'label': 1,
        'attack_type': 'port_scan'
    })

    # 4. Brute Force / Credential Exhaustion
    # Concentrated on 1-2 ports (SSH/RDP/FTP/HTTP Auth), massive connection failure count
    duration_brute = rng.uniform(400, 2500, size=n_brute)
    failed_brute = rng.normal(loc=50, scale=15, size=n_brute).clip(min=25)
    packets_brute = failed_brute * rng.uniform(1.8, 3.5, size=n_brute)
    bytes_brute = packets_brute * rng.uniform(70, 180, size=n_brute)
    syn_brute = (failed_brute * rng.uniform(0.7, 1.1, size=n_brute)).clip(min=15)
    dst_ports_brute = rng.choice([1, 2], size=n_brute, p=[0.92, 0.08])
    
    df_brute = pd.DataFrame({
        'duration_ms': np.round(duration_brute, 1),
        'packets': np.round(packets_brute).astype(int),
        'bytes': np.round(bytes_brute).astype(int),
        'syn_count': np.round(syn_brute).astype(int),
        'unique_dst_ports': dst_ports_brute.astype(int),
        'failed_connections': np.round(failed_brute).astype(int),
        'label': 1,
        'attack_type': 'brute_force'
    })

    df = pd.concat([df_normal, df_dos, df_scan, df_brute], ignore_index=True)
    df = df.sample(frac=1.0, random_state=random_state).reset_index(drop=True)
    return df

def train_and_evaluate(dataset_size: int = 8000, output_dir: str = 'backend') -> dict:
    print(f"Generating balanced network intrusion benchmark ({dataset_size} flows)...")
    df = generate_intrusion_dataset(n_samples=dataset_size, random_state=42)
    
    X = df[FEATURES]
    y = df['label']
    
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    
    pipeline = Pipeline([
        ('scaler', StandardScaler()),
        ('classifier', RandomForestClassifier(
            n_estimators=150,
            max_depth=12,
            min_samples_split=3,
            class_weight='balanced',
            random_state=42,
            n_jobs=-1
        ))
    ])
    
    pipeline.fit(X_train, y_train)
    
    y_pred = pipeline.predict(X_test)
    y_prob = pipeline.predict_proba(X_test)[:, 1]
    
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    roc_auc = roc_auc_score(y_test, y_prob)
    cm = confusion_matrix(y_test, y_pred).tolist()
    
    rf = pipeline.named_steps['classifier']
    importances = {feat: round(float(imp), 4) for feat, imp in zip(FEATURES, rf.feature_importances_)}
    sorted_importances = dict(sorted(importances.items(), key=lambda x: x[1], reverse=True))

    metrics = {
        'model_name': 'SentinelAI Random Forest Intrusion Classifier',
        'algorithm': 'RandomForestClassifier (150 estimators, max_depth=12) with StandardScaler',
        'dataset_benchmark': 'Network Flow Intrusion Synthesis (CIC-IDS2017 / NSL-KDD aligned features)',
        'total_samples': len(df),
        'train_samples': len(X_train),
        'test_samples': len(X_test),
        'features': FEATURES,
        'metrics': {
            'accuracy': round(float(acc), 4),
            'precision': round(float(prec), 4),
            'recall': round(float(rec), 4),
            'f1_score': round(float(f1), 4),
            'roc_auc': round(float(roc_auc), 4),
        },
        'confusion_matrix': {
            'true_negative': cm[0][0],
            'false_positive': cm[0][1],
            'false_negative': cm[1][0],
            'true_positive': cm[1][1],
            'matrix_2x2': cm
        },
        'feature_importances': sorted_importances,
        'class_distribution': {
            'benign_count': int((y == 0).sum()),
            'suspicious_count': int((y == 1).sum()),
            'attack_breakdown': df['attack_type'].value_counts().to_dict()
        }
    }
    
    os.makedirs(output_dir, exist_ok=True)
    model_path = os.path.join(output_dir, 'sentinel_model.joblib')
    metrics_path = os.path.join(output_dir, 'model_metrics.json')
    
    joblib.dump(pipeline, model_path)
    with open(metrics_path, 'w', encoding='utf-8') as f:
        json.dump(metrics, f, indent=2)
        
    print(f"Model saved to {model_path}")
    print(f"Results: F1={f1:.4f}, Accuracy={acc:.4f}, Precision={prec:.4f}, Recall={rec:.4f}, ROC_AUC={roc_auc:.4f}")
    return metrics

if __name__ == '__main__':
    train_and_evaluate()
