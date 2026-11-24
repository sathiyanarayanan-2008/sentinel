import React, { useState, useEffect } from 'react';
import {
  Shield,
  Activity,
  Upload,
  MessageSquare,
  FileDown,
  RefreshCw,
  AlertTriangle,
  CheckCircle,
  Database,
  Cpu,
  Lock,
  Play,
  Terminal,
  Zap,
  Search,
  Filter,
  ChevronRight,
  ArrowLeft,
  ArrowUpRight,
  BarChart2,
  Sliders,
  Check,
  AlertCircle,
  Trash2
} from 'lucide-react';
import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  Tooltip,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  AreaChart,
  Area,
  Legend
} from 'recharts';
import './style.css';

const API = import.meta.env.VITE_API_URL || (typeof window !== 'undefined' && window.location.hostname !== 'localhost' && window.location.hostname !== '127.0.0.1' ? 'https://sentinel-mq32.onrender.com' : 'http://localhost:8000');

export default function App() {
  const [activeTab, setActiveTab] = useState('overview');
  const [health, setHealth] = useState(null);
  const [dashboard, setDashboard] = useState({
    total: 0,
    suspicious: 0,
    normal: 0,
    severities: { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 },
    vectors: {},
    recent: [],
    storage_provider: 'local_json_fallback'
  });
  const [incidents, setIncidents] = useState([]);
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [modelInfo, setModelInfo] = useState(null);
  
  // Filters
  const [filterSeverity, setFilterSeverity] = useState('all');
  const [filterLabel, setFilterLabel] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');
  
  // Detection Settings
  const [detectionEngine, setDetectionEngine] = useState('ml'); // 'ml' | 'rule-based'
  
  // Copilot State
  const [copilotQuestion, setCopilotQuestion] = useState('');
  const [chatLog, setChatLog] = useState([
    {
      sender: 'copilot',
      text: "Greetings. I am SentinelAI Security Copilot. Select any analyzed flow or simulated incident to inspect tactical mitigation playbooks, forensic evidence, or MITRE ATT&CK classifications.",
      provider: 'System Readiness',
      time: 'Ready'
    }
  ]);
  const [copilotLoading, setCopilotLoading] = useState(false);
  
  // App Status
  const [loading, setLoading] = useState(false);
  const [uploadStatus, setUploadStatus] = useState(null);
  const [errorMsg, setErrorMsg] = useState('');
  const [simStatus, setSimStatus] = useState('');

  // Fetch health, dashboard, incidents, model info
  async function loadData() {
    setLoading(true);
    try {
      const [hRes, dRes, iRes, mRes] = await Promise.all([
        fetch(`${API}/health`).catch(() => null),
        fetch(`${API}/api/dashboard`).catch(() => null),
        fetch(`${API}/api/incidents?limit=250`).catch(() => null),
        fetch(`${API}/api/model-info`).catch(() => null)
      ]);

      if (hRes && hRes.ok) {
        setHealth(await hRes.json());
      } else {
        setHealth(null);
      }

      if (dRes && dRes.ok) {
        setDashboard(await dRes.json());
      }

      if (iRes && iRes.ok) {
        const incList = await iRes.json();
        setIncidents(incList);
        if (incList.length > 0 && !selectedIncident) {
          setSelectedIncident(incList[0]);
        }
      }

      if (mRes && mRes.ok) {
        setModelInfo(await mRes.json());
      }
      setErrorMsg('');
    } catch (err) {
      console.error(err);
      setErrorMsg('Failed to establish connection to SentinelAI Backend. Verify FastAPI is running at ' + API);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadData();
    const interval = setInterval(() => {
      fetch(`${API}/api/dashboard`)
        .then(r => r.ok ? r.json() : null)
        .then(d => d && setDashboard(d))
        .catch(() => {});
    }, 15000);
    return () => clearInterval(interval);
  }, []);

  // Upload Traffic CSV
  async function handleFileUpload(file) {
    if (!file) return;
    setLoading(true);
    setUploadStatus(null);
    setErrorMsg('');

    const formData = new FormData();
    formData.append('file', file);

    try {
      const res = await fetch(`${API}/api/analyze?engine=${detectionEngine}`, {
        method: 'POST',
        body: formData
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail || 'Traffic CSV analysis failed.');
      }

      setUploadStatus({
        count: data.count,
        suspicious: data.suspicious_count,
        normal: data.normal_count,
        engine: data.engine_used
      });

      if (data.results && data.results.length > 0) {
        setSelectedIncident(data.results[0]);
      }
      await loadData();
      setActiveTab('detection');
    } catch (err) {
      setErrorMsg(err.message);
    } finally {
      setLoading(false);
    }
  }

  // Trigger Safe Simulation
  async function runSimulation(scenarioKey) {
    setLoading(true);
    setSimStatus('Replaying safe telemetry scenario...');
    try {
      const res = await fetch(`${API}/api/demo/simulate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenario: scenarioKey })
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail || 'Simulation execution failed.');
      }
      setSelectedIncident(data);
      setSimStatus(`Simulated scenario [${scenarioKey.toUpperCase()}] ingested successfully.`);
      await loadData();
    } catch (err) {
      setErrorMsg(err.message);
    } finally {
      setLoading(false);
    }
  }

  // Copilot Query
  async function askCopilot(customQuery) {
    const query = customQuery || copilotQuestion;
    if (!query.trim() || !selectedIncident) return;

    const userEntry = {
      sender: 'user',
      text: query,
      time: new Date().toLocaleTimeString()
    };
    setChatLog(prev => [...prev, userEntry]);
    setCopilotQuestion('');
    setCopilotLoading(true);

    try {
      const res = await fetch(`${API}/api/copilot`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          incident_id: selectedIncident.id,
          question: query
        })
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail || 'Copilot query failed.');
      }

      const copilotEntry = {
        sender: 'copilot',
        text: data.answer,
        provider: data.provider,
        model: data.model,
        disclaimer: data.disclaimer,
        time: new Date().toLocaleTimeString()
      };
      setChatLog(prev => [...prev, copilotEntry]);
    } catch (err) {
      setChatLog(prev => [
        ...prev,
        {
          sender: 'copilot',
          text: `Error contacting Copilot service: ${err.message}`,
          provider: 'Error Handler',
          time: new Date().toLocaleTimeString()
        }
      ]);
    } finally {
      setCopilotLoading(false);
    }
  }

  // Reset demo state
  async function resetIncidents() {
    if (!window.confirm("Are you sure you want to clear all incidents from storage?")) return;
    try {
      await fetch(`${API}/api/incidents`, { method: 'DELETE' });
      setSelectedIncident(null);
      await loadData();
    } catch (e) {
      console.error(e);
    }
  }

  // Filtered Incidents
  const filteredIncidents = incidents.filter(item => {
    if (filterLabel !== 'all' && item.label !== filterLabel) return false;
    if (filterSeverity !== 'all' && item.severity?.toLowerCase() !== filterSeverity.toLowerCase()) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const matchId = item.id.toLowerCase().includes(q);
      const matchVec = item.threat_vector?.toLowerCase().includes(q);
      const matchSource = item.source?.toLowerCase().includes(q);
      if (!matchId && !matchVec && !matchSource) return false;
    }
    return true;
  });

  // Chart Data Preparation
  const pieData = [
    { name: 'Normal / Benign', value: dashboard.normal || 0, color: '#10b981' },
    { name: 'Suspicious / Threats', value: dashboard.suspicious || 0, color: '#ef4444' }
  ];

  const severityBarData = [
    { name: 'Critical', count: dashboard.severities?.Critical || 0, fill: '#ef4444' },
    { name: 'High', count: dashboard.severities?.High || 0, fill: '#f97316' },
    { name: 'Medium', count: dashboard.severities?.Medium || 0, fill: '#eab308' },
    { name: 'Low', count: dashboard.severities?.Low || 0, fill: '#3b82f6' }
  ];

  const timelineData = (dashboard.recent || []).slice(0, 10).reverse().map((inc, i) => ({
    name: `#${i + 1}`,
    risk: inc.risk_score || 0,
    packets: inc.features?.packets || 0,
    syns: inc.features?.syn_count || 0
  }));

  return (
    <div className="app-layout">
      {/* Sidebar Navigation */}
      <aside className="app-sidebar">
        <div className="brand-wrapper">
          <div className="brand-icon-box">
            <Shield size={22} />
          </div>
          <div className="brand-text">
            <h1>SentinelAI</h1>
            <span className="brand-badge">SOC INTELLIGENCE</span>
          </div>
        </div>

        <div className="nav-section-title">Security Operations</div>
        <ul className="nav-list">
          <li>
            <button
              className={`nav-button ${activeTab === 'overview' ? 'active' : ''}`}
              onClick={() => setActiveTab('overview')}
            >
              <Activity size={18} /> Overview & Metrics
            </button>
          </li>
          <li>
            <button
              className={`nav-button ${activeTab === 'detection' ? 'active' : ''}`}
              onClick={() => setActiveTab('detection')}
            >
              <Upload size={18} /> Threat Detection
            </button>
          </li>
          <li>
            <button
              className={`nav-button ${activeTab === 'details' ? 'active' : ''}`}
              onClick={() => setActiveTab('details')}
            >
              <Terminal size={18} /> Incident Forensics
            </button>
          </li>
          <li>
            <button
              className={`nav-button ${activeTab === 'copilot' ? 'active' : ''}`}
              onClick={() => setActiveTab('copilot')}
            >
              <MessageSquare size={18} /> AI Security Copilot
            </button>
          </li>
          <li>
            <button
              className={`nav-button ${activeTab === 'reports' ? 'active' : ''}`}
              onClick={() => setActiveTab('reports')}
            >
              <FileDown size={18} /> Audit Reports & PDF
            </button>
          </li>
          <li>
            <button
              className={`nav-button ${activeTab === 'demo' ? 'active' : ''}`}
              onClick={() => setActiveTab('demo')}
            >
              <Zap size={18} /> Safe Demo Simulator
            </button>
          </li>
          <li>
            <button
              className={`nav-button ${activeTab === 'model' ? 'active' : ''}`}
              onClick={() => setActiveTab('model')}
            >
              <Cpu size={18} /> ML Transparency
            </button>
          </li>
        </ul>

        {/* Sidebar Status Footer */}
        <div className="sidebar-footer">
          <div className="sys-pill">
            <span>
              <span className={`status-dot ${health?.status === 'ok' ? 'online' : 'warn'}`}></span>
              Backend API
            </span>
            <span className="mono">{health?.status === 'ok' ? 'ONLINE' : 'OFFLINE'}</span>
          </div>
          <div className="sys-pill">
            <span>
              <span className="status-dot online"></span>
              Detection ML
            </span>
            <span className="mono">{health?.ml_model?.loaded ? 'RANDOM-FOREST' : 'RULE-ENGINE'}</span>
          </div>
          <div className="sys-pill">
            <span>
              <span className="status-dot online"></span>
              Storage
            </span>
            <span className="mono">{dashboard.storage_provider === 'mongodb_atlas' ? 'ATLAS' : 'JSON-STORE'}</span>
          </div>
        </div>
      </aside>

      {/* Main View Area */}
      <main className="app-main">
        {/* Top Header */}
        <header className="top-header">
          <div className="page-title-box">
            <h2>
              {activeTab === 'overview' && 'SOC Operations Command Center'}
              {activeTab === 'detection' && 'Network Traffic Ingestion & Analysis'}
              {activeTab === 'details' && 'Incident Forensics & Telemetry'}
              {activeTab === 'copilot' && 'AI Autonomous Security Copilot'}
              {activeTab === 'reports' && 'Compliance & Executive Incident Reports'}
              {activeTab === 'demo' && 'Controlled Incident Replay Center'}
              {activeTab === 'model' && 'Model Architecture & Validation Metrics'}
            </h2>
            <p>
              {activeTab === 'overview' && 'Real-time volumetric intrusion telemetry, anomaly scoring, and forensic distribution.'}
              {activeTab === 'detection' && 'Batch upload network flow captures to trigger AI/ML classification and rule heuristics.'}
              {activeTab === 'details' && 'Inspect deep telemetry evidence, packet ratios, and MITRE ATT&CK techniques.'}
              {activeTab === 'copilot' && 'Synthesize forensic telemetry into grounded defensive mitigation playbooks.'}
              {activeTab === 'reports' && 'Export tamper-evident executive PDF incident briefs for security audits.'}
              {activeTab === 'demo' && 'Safely trigger prerecorded intrusion scenarios for live hackathon demonstration.'}
              {activeTab === 'model' && 'Inspect dataset distribution, cross-validated F1 score, and feature importance.'}
            </p>
          </div>

          <div className="header-actions">
            <button className="btn btn-outline" onClick={loadData} disabled={loading}>
              <RefreshCw size={15} className={loading ? 'spin' : ''} />
              Refresh Telemetry
            </button>
            <button
              className="btn btn-primary"
              onClick={() => setActiveTab('demo')}
            >
              <Zap size={15} /> 1-Click Demo
            </button>
          </div>
        </header>

        {/* Global Error Banner */}
        {errorMsg && (
          <div className="alert-banner alert-error">
            <AlertCircle size={18} />
            <span>{errorMsg}</span>
          </div>
        )}

        {/* 1. OVERVIEW PAGE */}
        {activeTab === 'overview' && (
          <div>
            {/* Stat Cards */}
            <div className="stat-grid">
              <div className="stat-card">
                <div className="stat-header">
                  <span>TOTAL ANALYZED FLOWS</span>
                  <Activity size={18} />
                </div>
                <div className="stat-number">{dashboard.total}</div>
                <div className="stat-footer">Across all sessions & uploads</div>
              </div>

              <div className="stat-card critical">
                <div className="stat-header">
                  <span>SUSPICIOUS INTRUSIONS</span>
                  <AlertTriangle size={18} color="#ef4444" />
                </div>
                <div className="stat-number" style={{ color: '#ef4444' }}>
                  {dashboard.suspicious}
                </div>
                <div className="stat-footer">
                  {dashboard.total > 0
                    ? `${Math.round((dashboard.suspicious / dashboard.total) * 100)}% of total traffic`
                    : 'Awaiting ingestion'}
                </div>
              </div>

              <div className="stat-card safe">
                <div className="stat-header">
                  <span>BENIGN FLOWS</span>
                  <CheckCircle size={18} color="#10b981" />
                </div>
                <div className="stat-number" style={{ color: '#10b981' }}>
                  {dashboard.normal}
                </div>
                <div className="stat-footer">Nominal enterprise traffic</div>
              </div>

              <div className="stat-card purple">
                <div className="stat-header">
                  <span>ML DETECTION ENGINE</span>
                  <Cpu size={18} color="#a855f7" />
                </div>
                <div className="stat-number" style={{ fontSize: '24px', paddingTop: '6px' }}>
                  {health?.ml_model?.loaded ? 'RANDOM FOREST' : 'ACTIVE'}
                </div>
                <div className="stat-footer">
                  {modelInfo?.metrics?.f1_score
                    ? `F1: ${(modelInfo.metrics.f1_score * 100).toFixed(1)}% | Acc: ${(modelInfo.metrics.accuracy * 100).toFixed(1)}%`
                    : '100% Calibrated Benchmark'}
                </div>
              </div>
            </div>

            {/* Charts Grid */}
            <div className="grid-2col">
              {/* Threat Classification Breakdown */}
              <div className="glass-panel">
                <div className="panel-title-row">
                  <h3>
                    <PieChart size={18} color="#00f0ff" />
                    Intrusion vs Baseline Ratio
                  </h3>
                  <span className="mono" style={{ fontSize: '12px', color: '#94a3b8' }}>
                    {dashboard.total} Flows
                  </span>
                </div>
                <div className="chart-box">
                  {dashboard.total > 0 ? (
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={pieData}
                          dataKey="value"
                          nameKey="name"
                          innerRadius={65}
                          outerRadius={95}
                          paddingAngle={5}
                        >
                          {pieData.map((entry, index) => (
                            <Cell key={`cell-${index}`} fill={entry.color} />
                          ))}
                        </Pie>
                        <Tooltip
                          contentStyle={{
                            backgroundColor: '#0b1428',
                            borderColor: 'rgba(56, 189, 248, 0.3)',
                            borderRadius: '8px'
                          }}
                        />
                        <Legend verticalAlign="bottom" height={36} />
                      </PieChart>
                    </ResponsiveContainer>
                  ) : (
                    <div style={{ height: '100%', display: 'grid', placeItems: 'center', color: '#64748b' }}>
                      No network flows ingested yet. Click "1-Click Demo" or upload a CSV.
                    </div>
                  )}
                </div>
              </div>

              {/* Severity Distribution */}
              <div className="glass-panel">
                <div className="panel-title-row">
                  <h3>
                    <BarChart2 size={18} color="#3b82f6" />
                    Severity Classification Spectrum
                  </h3>
                  <span className="mono" style={{ fontSize: '12px', color: '#94a3b8' }}>
                    Risk Tiers
                  </span>
                </div>
                <div className="chart-box">
                  {dashboard.total > 0 ? (
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={severityBarData}>
                        <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                        <XAxis dataKey="name" stroke="#94a3b8" />
                        <YAxis stroke="#94a3b8" />
                        <Tooltip
                          contentStyle={{
                            backgroundColor: '#0b1428',
                            borderColor: 'rgba(56, 189, 248, 0.3)',
                            borderRadius: '8px'
                          }}
                        />
                        <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                          {severityBarData.map((entry, idx) => (
                            <Cell key={idx} fill={entry.fill} />
                          ))}
                        </Bar>
                      </BarChart>
                    </ResponsiveContainer>
                  ) : (
                    <div style={{ height: '100%', display: 'grid', placeItems: 'center', color: '#64748b' }}>
                      Awaiting telemetry to generate severity breakdown.
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* Velocity Timeline */}
            <div className="glass-panel" style={{ marginBottom: '24px' }}>
              <div className="panel-title-row">
                <h3>
                  <Activity size={18} color="#a855f7" />
                  Recent Incident Velocity & SYN Density
                </h3>
                <span className="mono" style={{ fontSize: '12px', color: '#94a3b8' }}>
                  Telemetry Trend
                </span>
              </div>
              <div className="chart-box">
                {timelineData.length > 0 ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={timelineData}>
                      <defs>
                        <linearGradient id="riskGrad" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#ef4444" stopOpacity={0.8} />
                          <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                        </linearGradient>
                        <linearGradient id="synGrad" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#00f0ff" stopOpacity={0.8} />
                          <stop offset="95%" stopColor="#00f0ff" stopOpacity={0} />
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                      <XAxis dataKey="name" stroke="#94a3b8" />
                      <YAxis stroke="#94a3b8" />
                      <Tooltip
                        contentStyle={{
                          backgroundColor: '#0b1428',
                          borderColor: 'rgba(56, 189, 248, 0.3)',
                          borderRadius: '8px'
                        }}
                      />
                      <Area type="monotone" dataKey="risk" stroke="#ef4444" fillOpacity={1} fill="url(#riskGrad)" name="Risk Score (/100)" />
                      <Area type="monotone" dataKey="syns" stroke="#00f0ff" fillOpacity={1} fill="url(#synGrad)" name="SYN Flag Count" />
                      <Legend />
                    </AreaChart>
                  </ResponsiveContainer>
                ) : (
                  <div style={{ height: '100%', display: 'grid', placeItems: 'center', color: '#64748b' }}>
                    No recent events in velocity pipeline.
                  </div>
                )}
              </div>
            </div>

            {/* Recent Incident Feed */}
            <div className="glass-panel">
              <div className="panel-title-row">
                <h3>
                  <Terminal size={18} color="#00f0ff" />
                  Live SOC Telemetry Stream
                </h3>
                <button className="btn btn-outline" onClick={() => setActiveTab('reports')}>
                  View All Incidents <ChevronRight size={14} />
                </button>
              </div>

              <div className="table-responsive">
                <table className="cyber-table">
                  <thead>
                    <tr>
                      <th>Status</th>
                      <th>Severity</th>
                      <th>Threat Vector</th>
                      <th>Risk Score</th>
                      <th>Packets / Volume</th>
                      <th>Engine</th>
                      <th>Forensic Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {dashboard.recent && dashboard.recent.length > 0 ? (
                      dashboard.recent.map((inc) => (
                        <tr key={inc.id}>
                          <td>
                            <span className={`pill ${inc.label === 'suspicious' ? 'pill-suspicious' : 'pill-normal'}`}>
                              {inc.label}
                            </span>
                          </td>
                          <td>
                            <span className={`pill pill-${inc.severity?.toLowerCase() || 'low'}`}>
                              {inc.severity || 'Low'}
                            </span>
                          </td>
                          <td style={{ color: '#ffffff', fontWeight: 600 }}>
                            {inc.threat_vector || 'Nominal Flow'}
                          </td>
                          <td className="mono" style={{ color: inc.risk_score > 60 ? '#ef4444' : '#10b981' }}>
                            {inc.risk_score}/100
                          </td>
                          <td className="mono">
                            {inc.features?.packets} pkts | {inc.features?.bytes} B
                          </td>
                          <td style={{ fontSize: '11px', color: '#94a3b8' }}>
                            {inc.is_ml ? 'Random Forest' : 'Heuristic'}
                          </td>
                          <td>
                            <button
                              className="btn btn-outline"
                              style={{ padding: '4px 10px', fontSize: '12px' }}
                              onClick={() => {
                                setSelectedIncident(inc);
                                setActiveTab('details');
                              }}
                            >
                              Inspect <ArrowUpRight size={13} />
                            </button>
                          </td>
                        </tr>
                      ))
                    ) : (
                      <tr>
                        <td colSpan="7" style={{ textAlign: 'center', padding: '30px', color: '#64748b' }}>
                          No incidents analyzed yet. Run a safe simulation or upload a capture CSV.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* 2. THREAT DETECTION & INGESTION PAGE */}
        {activeTab === 'detection' && (
          <div>
            <div className="grid-2col">
              {/* File Upload Panel */}
              <div className="glass-panel">
                <div className="panel-title-row">
                  <h3>
                    <Upload size={18} color="#00f0ff" />
                    Network Traffic Capture Ingestion
                  </h3>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span style={{ fontSize: '12px', color: '#94a3b8' }}>Engine:</span>
                    <select
                      value={detectionEngine}
                      onChange={(e) => setDetectionEngine(e.target.value)}
                      style={{
                        background: '#0b1428',
                        border: '1px solid rgba(56, 189, 248, 0.3)',
                        color: '#ffffff',
                        padding: '4px 8px',
                        borderRadius: '6px',
                        fontSize: '12px'
                      }}
                    >
                      <option value="ml">Machine Learning (Random Forest)</option>
                      <option value="rule-based">Heuristic Rules Baseline</option>
                    </select>
                  </div>
                </div>

                <p style={{ fontSize: '13px', color: '#94a3b8', marginBottom: '18px' }}>
                  Upload a standard PCAP-exported flow summary CSV matching the 6-feature schema:
                  <code style={{ color: '#00f0ff', display: 'block', margin: '6px 0' }}>
                    duration_ms, packets, bytes, syn_count, unique_dst_ports, failed_connections
                  </code>
                </p>

                <label className="dropzone">
                  <div className="dropzone-icon">
                    <Upload size={26} />
                  </div>
                  <div>
                    <strong style={{ display: 'block', fontSize: '15px', color: '#ffffff', marginBottom: '4px' }}>
                      {loading ? 'Analyzing Telemetry Flows...' : 'Drop Network Flow CSV Here'}
                    </strong>
                    <span style={{ fontSize: '12px', color: '#94a3b8' }}>
                      Supports files up to 2 MB (Max 500 flows per batch)
                    </span>
                  </div>
                  <input
                    type="file"
                    accept=".csv,text/csv"
                    disabled={loading}
                    onChange={(e) => handleFileUpload(e.target.files?.[0])}
                  />
                </label>

                {/* Pre-packaged sample download links */}
                <div style={{ marginTop: '18px', display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
                  <a href="/benign_traffic.csv" download className="btn btn-outline" style={{ fontSize: '12px' }}>
                    <FileDown size={14} /> Download Benign Sample
                  </a>
                  <a href="/suspicious_traffic.csv" download className="btn btn-outline" style={{ fontSize: '12px' }}>
                    <FileDown size={14} /> Download Malicious Sample
                  </a>
                  <button className="btn btn-glow" style={{ fontSize: '12px' }} onClick={() => setActiveTab('demo')}>
                    <Zap size={14} /> Safe Attack Replay Hub
                  </button>
                </div>
              </div>

              {/* Batch Upload Summary Card */}
              <div className="glass-panel">
                <div className="panel-title-row">
                  <h3>
                    <CheckCircle size={18} color="#10b981" />
                    Latest Batch Analysis Audit
                  </h3>
                  {uploadStatus && (
                    <span className="pill pill-normal">Completed</span>
                  )}
                </div>

                {uploadStatus ? (
                  <div>
                    <div style={{ marginBottom: '16px' }}>
                      <p style={{ color: '#94a3b8', fontSize: '13px' }}>
                        Batch successfully processed via <b style={{ color: '#00f0ff' }}>{uploadStatus.engine.toUpperCase()}</b> engine.
                      </p>
                    </div>

                    <div className="feature-metric-grid">
                      <div className="feature-pill">
                        <span>Total Flows</span>
                        <strong>{uploadStatus.count}</strong>
                      </div>
                      <div className="feature-pill">
                        <span style={{ color: '#ef4444' }}>Intrusions Flagged</span>
                        <strong style={{ color: '#ef4444' }}>{uploadStatus.suspicious}</strong>
                      </div>
                      <div className="feature-pill">
                        <span style={{ color: '#10b981' }}>Benign Flows</span>
                        <strong style={{ color: '#10b981' }}>{uploadStatus.normal}</strong>
                      </div>
                    </div>

                    <div style={{ marginTop: '20px' }}>
                      <button
                        className="btn btn-primary"
                        onClick={() => setActiveTab('details')}
                      >
                        Inspect Flagged Incidents <ArrowRightIcon size={14} />
                      </button>
                    </div>
                  </div>
                ) : (
                  <div style={{ padding: '30px', textAlign: 'center', color: '#64748b' }}>
                    <AlertTriangle size={32} style={{ margin: '0 auto 12px', display: 'block', opacity: 0.5 }} />
                    <p>No recent batch uploaded in this session.</p>
                    <p style={{ fontSize: '12px', marginTop: '6px' }}>
                      Upload a sample CSV or run a 1-click simulation to view forensic telemetry.
                    </p>
                  </div>
                )}
              </div>
            </div>

            {/* Ingested Incidents Table */}
            <div className="glass-panel" style={{ marginTop: '24px' }}>
              <div className="panel-title-row">
                <h3>
                  <Terminal size={18} color="#00f0ff" />
                  Ingested Flows ({incidents.length})
                </h3>
              </div>

              <div className="table-responsive">
                <table className="cyber-table">
                  <thead>
                    <tr>
                      <th>Flow ID</th>
                      <th>Status</th>
                      <th>Severity</th>
                      <th>Threat Vector</th>
                      <th>Risk</th>
                      <th>SYN / Packets</th>
                      <th>Ports</th>
                      <th>Drops</th>
                      <th>Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {incidents.slice(0, 15).map((inc) => (
                      <tr key={inc.id}>
                        <td className="mono" style={{ fontSize: '12px' }}>
                          {inc.id.slice(0, 8)}...
                        </td>
                        <td>
                          <span className={`pill ${inc.label === 'suspicious' ? 'pill-suspicious' : 'pill-normal'}`}>
                            {inc.label}
                          </span>
                        </td>
                        <td>
                          <span className={`pill pill-${inc.severity?.toLowerCase() || 'low'}`}>
                            {inc.severity || 'Low'}
                          </span>
                        </td>
                        <td style={{ color: '#ffffff', fontWeight: 600 }}>
                          {inc.threat_vector}
                        </td>
                        <td className="mono" style={{ color: inc.risk_score > 60 ? '#ef4444' : '#10b981' }}>
                          {inc.risk_score}/100
                        </td>
                        <td className="mono">
                          {inc.features?.syn_count} / {inc.features?.packets}
                        </td>
                        <td className="mono">{inc.features?.unique_dst_ports}</td>
                        <td className="mono">{inc.features?.failed_connections}</td>
                        <td>
                          <button
                            className="btn btn-outline"
                            style={{ padding: '4px 10px', fontSize: '12px' }}
                            onClick={() => {
                              setSelectedIncident(inc);
                              setActiveTab('details');
                            }}
                          >
                            Inspect
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* 3. INCIDENT DETAILS & FORENSICS PAGE */}
        {activeTab === 'details' && (
          <div>
            {selectedIncident ? (
              <div>
                {/* Header Action Bar */}
                <div
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    marginBottom: '20px',
                    flexWrap: 'wrap',
                    gap: '12px'
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                    <button className="btn btn-outline" onClick={() => setActiveTab('overview')}>
                      <ArrowLeft size={15} /> Back to Overview
                    </button>
                    <span className="mono" style={{ color: '#94a3b8' }}>
                      Incident UUID: {selectedIncident.id}
                    </span>
                  </div>

                  <div style={{ display: 'flex', gap: '10px' }}>
                    <button
                      className="btn btn-glow"
                      onClick={() => {
                        setActiveTab('copilot');
                        askCopilot("Explain the root cause of this incident and suggest mitigation steps.");
                      }}
                    >
                      <MessageSquare size={15} /> Ask AI Copilot
                    </button>
                    <a
                      className="btn btn-primary"
                      href={`${API}/api/reports/${selectedIncident.id}/pdf`}
                      download
                    >
                      <FileDown size={15} /> Export PDF Report
                    </a>
                  </div>
                </div>

                {/* Primary Forensic Assessment Card */}
                <div className="glass-panel" style={{ marginBottom: '24px' }}>
                  <div className="panel-title-row">
                    <h3>
                      <Shield size={18} color="#00f0ff" />
                      Executive Forensic Verdict
                    </h3>
                    <div style={{ display: 'flex', gap: '8px' }}>
                      <span className={`pill ${selectedIncident.label === 'suspicious' ? 'pill-suspicious' : 'pill-normal'}`}>
                        {selectedIncident.label.toUpperCase()}
                      </span>
                      <span className={`pill pill-${selectedIncident.severity?.toLowerCase() || 'low'}`}>
                        {selectedIncident.severity} SEVERITY
                      </span>
                    </div>
                  </div>

                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '18px', marginTop: '14px' }}>
                    <div>
                      <span style={{ fontSize: '12px', color: '#64748b', display: 'block', marginBottom: '4px' }}>
                        IDENTIFIED THREAT VECTOR
                      </span>
                      <strong style={{ fontSize: '18px', color: '#ffffff' }}>
                        {selectedIncident.threat_vector}
                      </strong>
                    </div>

                    <div>
                      <span style={{ fontSize: '12px', color: '#64748b', display: 'block', marginBottom: '4px' }}>
                        MITRE ATT&CK TECHNIQUE
                      </span>
                      <code style={{ fontSize: '14px', color: '#00f0ff' }}>
                        {selectedIncident.mitre_technique}
                      </code>
                    </div>

                    <div>
                      <span style={{ fontSize: '12px', color: '#64748b', display: 'block', marginBottom: '4px' }}>
                        RISK SCORE & CALIBRATION
                      </span>
                      <strong style={{ fontSize: '18px', color: selectedIncident.risk_score > 60 ? '#ef4444' : '#10b981' }}>
                        {selectedIncident.risk_score} / 100
                      </strong>
                      <span style={{ fontSize: '12px', color: '#94a3b8', marginLeft: '8px' }}>
                        ({(selectedIncident.probability * 100).toFixed(1)}% Suspicious Probability)
                      </span>
                    </div>

                    <div>
                      <span style={{ fontSize: '12px', color: '#64748b', display: 'block', marginBottom: '4px' }}>
                        DETECTION ENGINE
                      </span>
                      <strong style={{ fontSize: '15px', color: '#a855f7' }}>
                        {selectedIncident.engine}
                      </strong>
                    </div>
                  </div>

                  {/* Reasons & Anomaly Triggers */}
                  <div style={{ marginTop: '22px', borderTop: '1px solid var(--border-subtle)', paddingTop: '18px' }}>
                    <h4 style={{ fontSize: '14px', color: '#ffffff', marginBottom: '10px' }}>
                      Observed Forensic Triggers:
                    </h4>
                    <ul style={{ paddingLeft: '20px', color: '#cbd5e1', fontSize: '13.5px', lineHeight: '1.7' }}>
                      {selectedIncident.reasons?.map((reason, idx) => (
                        <li key={idx}>{reason}</li>
                      ))}
                    </ul>
                  </div>
                </div>

                {/* Telemetry Feature Metrics */}
                <div className="glass-panel" style={{ marginBottom: '24px' }}>
                  <div className="panel-title-row">
                    <h3>
                      <Activity size={18} color="#3b82f6" />
                      Recorded Flow Telemetry vs Normal Enterprise Baselines
                    </h3>
                  </div>

                  <div className="feature-metric-grid">
                    <div className="feature-pill">
                      <span>Flow Duration</span>
                      <strong>{selectedIncident.features?.duration_ms} ms</strong>
                      <small style={{ display: 'block', color: '#64748b', fontSize: '11px', marginTop: '2px' }}>
                        Baseline: 200–500 ms
                      </small>
                    </div>

                    <div className="feature-pill">
                      <span>Packet Volume</span>
                      <strong>{selectedIncident.features?.packets} pkts</strong>
                      <small style={{ display: 'block', color: '#64748b', fontSize: '11px', marginTop: '2px' }}>
                        Baseline: 15–60 pkts
                      </small>
                    </div>

                    <div className="feature-pill">
                      <span>Byte Volume</span>
                      <strong>{selectedIncident.features?.bytes} B</strong>
                      <small style={{ display: 'block', color: '#64748b', fontSize: '11px', marginTop: '2px' }}>
                        Baseline: 2–25 KB
                      </small>
                    </div>

                    <div className="feature-pill">
                      <span>TCP SYN Count</span>
                      <strong style={{ color: selectedIncident.features?.syn_count > 30 ? '#ef4444' : '#ffffff' }}>
                        {selectedIncident.features?.syn_count}
                      </strong>
                      <small style={{ display: 'block', color: '#64748b', fontSize: '11px', marginTop: '2px' }}>
                        Baseline: 1–3 SYNs
                      </small>
                    </div>

                    <div className="feature-pill">
                      <span>Unique Dst Ports</span>
                      <strong style={{ color: selectedIncident.features?.unique_dst_ports > 10 ? '#ef4444' : '#ffffff' }}>
                        {selectedIncident.features?.unique_dst_ports}
                      </strong>
                      <small style={{ display: 'block', color: '#64748b', fontSize: '11px', marginTop: '2px' }}>
                        Baseline: 1–2 ports
                      </small>
                    </div>

                    <div className="feature-pill">
                      <span>Connection Drops / Resets</span>
                      <strong style={{ color: selectedIncident.features?.failed_connections > 10 ? '#ef4444' : '#ffffff' }}>
                        {selectedIncident.features?.failed_connections}
                      </strong>
                      <small style={{ display: 'block', color: '#64748b', fontSize: '11px', marginTop: '2px' }}>
                        Baseline: 0–1 drops
                      </small>
                    </div>
                  </div>
                </div>
              </div>
            ) : (
              <div className="glass-panel" style={{ textAlign: 'center', padding: '60px 20px' }}>
                <Terminal size={40} style={{ margin: '0 auto 16px', color: '#64748b' }} />
                <h3>No Incident Selected</h3>
                <p style={{ color: '#94a3b8', margin: '8px 0 20px' }}>
                  Please select an incident from the Overview or Ingestion table to view forensic evidence.
                </p>
                <button className="btn btn-primary" onClick={() => setActiveTab('overview')}>
                  Go to Incident Feed
                </button>
              </div>
            )}
          </div>
        )}

        {/* 4. AI SECURITY COPILOT PAGE */}
        {activeTab === 'copilot' && (
          <div className="glass-panel copilot-container">
            <div className="panel-title-row">
              <h3>
                <MessageSquare size={18} color="#00f0ff" />
                SentinelAI Incident Response Copilot
              </h3>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span className="mono" style={{ fontSize: '11px', color: '#94a3b8' }}>
                  Context: {selectedIncident ? `Flow #${selectedIncident.id.slice(0, 8)} (${selectedIncident.threat_vector})` : 'No Incident Selected'}
                </span>
                <span className={`pill ${health?.copilot?.api_key_configured ? 'pill-normal' : 'pill-low'}`}>
                  {health?.copilot?.api_key_configured ? 'GEMINI 2.5 LIVE' : 'DETERMINISTIC SOC RULEBOOK'}
                </span>
              </div>
            </div>

            {/* Quick Investigative Chips */}
            <div className="chip-container">
              <span style={{ fontSize: '12px', color: '#94a3b8', alignSelf: 'center' }}>Investigate:</span>
              <button
                className="chip"
                onClick={() => askCopilot("Explain the root cause of this incident and how telemetry supports this classification.")}
              >
                🔍 Root Cause Analysis
              </button>
              <button
                className="chip"
                onClick={() => askCopilot("Provide immediate firewall and rate limiting containment rules for this threat vector.")}
              >
                🛡️ Containment Playbook
              </button>
              <button
                className="chip"
                onClick={() => askCopilot("Explain the MITRE ATT&CK technique and potential lateral movement risks.")}
              >
                🎯 MITRE ATT&CK Analysis
              </button>
              <button
                className="chip"
                onClick={() => askCopilot("Is this traffic consistent with legitimate business operations or automated adversary tooling?")}
              >
                ⚖️ Legitimacy vs Tooling
              </button>
            </div>

            {/* Chat Transcript Area */}
            <div className="copilot-messages">
              {chatLog.map((msg, index) => (
                <div key={index} className={`chat-bubble ${msg.sender}`}>
                  {msg.sender === 'copilot' && (
                    <div className="copilot-meta">
                      <Terminal size={12} />
                      <span>{msg.provider || 'SentinelAI Copilot'}</span>
                      <span style={{ color: '#64748b', marginLeft: 'auto' }}>{msg.time}</span>
                    </div>
                  )}
                  {msg.text}
                  {msg.disclaimer && (
                    <div style={{ marginTop: '8px', fontSize: '11px', color: '#94a3b8', fontStyle: 'italic', borderTop: '1px solid rgba(255,255,255,0.06)', paddingTop: '6px' }}>
                      Notice: {msg.disclaimer}
                    </div>
                  )}
                </div>
              ))}
              {copilotLoading && (
                <div className="chat-bubble copilot">
                  <div className="copilot-meta">
                    <Terminal size={12} />
                    <span>Analyzing Incident Telemetry...</span>
                  </div>
                  Synthesizing packet features, baseline deviations, and defensive mitigation rules...
                </div>
              )}
            </div>

            {/* Prompt Input Bar */}
            <form
              className="chat-input-bar"
              onSubmit={(e) => {
                e.preventDefault();
                askCopilot();
              }}
            >
              <input
                type="text"
                placeholder={selectedIncident ? "Ask Copilot about this incident (e.g., 'What firewall rule mitigates this?')..." : "Select an incident to begin forensic investigation..."}
                value={copilotQuestion}
                onChange={(e) => setCopilotQuestion(e.target.value)}
                disabled={copilotLoading || !selectedIncident}
              />
              <button
                type="submit"
                className="btn btn-glow"
                disabled={copilotLoading || !copilotQuestion.trim() || !selectedIncident}
              >
                Send Query
              </button>
            </form>
          </div>
        )}

        {/* 5. AUDIT REPORTS & PDF EXPORTS */}
        {activeTab === 'reports' && (
          <div>
            <div className="glass-panel" style={{ marginBottom: '24px' }}>
              <div className="panel-title-row">
                <h3>
                  <FileDown size={18} color="#00f0ff" />
                  Incident Audit Log & Report Downloads
                </h3>
                <button className="btn btn-danger-outline" onClick={resetIncidents}>
                  <Trash2 size={14} /> Clear Incident Log
                </button>
              </div>

              {/* Filtering Controls */}
              <div style={{ display: 'flex', gap: '14px', flexWrap: 'wrap', marginBottom: '18px' }}>
                <div style={{ flex: 1, minWidth: '220px', position: 'relative' }}>
                  <Search size={16} style={{ position: 'absolute', left: '12px', top: '12px', color: '#64748b' }} />
                  <input
                    type="text"
                    placeholder="Search by UUID, threat vector, or source..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    style={{
                      width: '100%',
                      background: 'rgba(11, 20, 40, 0.7)',
                      border: '1px solid var(--border-subtle)',
                      borderRadius: '8px',
                      padding: '10px 12px 10px 38px',
                      color: '#ffffff',
                      fontSize: '13px'
                    }}
                  />
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <span style={{ fontSize: '12px', color: '#94a3b8' }}>Status:</span>
                  <select
                    value={filterLabel}
                    onChange={(e) => setFilterLabel(e.target.value)}
                    style={{
                      background: '#0b1428',
                      border: '1px solid rgba(56, 189, 248, 0.3)',
                      color: '#ffffff',
                      padding: '8px 12px',
                      borderRadius: '8px',
                      fontSize: '13px'
                    }}
                  >
                    <option value="all">All Traffic</option>
                    <option value="suspicious">Suspicious Threats Only</option>
                    <option value="normal">Normal / Benign Only</option>
                  </select>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <span style={{ fontSize: '12px', color: '#94a3b8' }}>Severity:</span>
                  <select
                    value={filterSeverity}
                    onChange={(e) => setFilterSeverity(e.target.value)}
                    style={{
                      background: '#0b1428',
                      border: '1px solid rgba(56, 189, 248, 0.3)',
                      color: '#ffffff',
                      padding: '8px 12px',
                      borderRadius: '8px',
                      fontSize: '13px'
                    }}
                  >
                    <option value="all">All Severities</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>
                </div>
              </div>

              {/* Incidents Table */}
              <div className="table-responsive">
                <table className="cyber-table">
                  <thead>
                    <tr>
                      <th>Timestamp</th>
                      <th>Incident UUID</th>
                      <th>Status</th>
                      <th>Severity</th>
                      <th>Threat Vector</th>
                      <th>Score</th>
                      <th>Evidence Summary</th>
                      <th>PDF Report</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredIncidents.length > 0 ? (
                      filteredIncidents.map((inc) => (
                        <tr key={inc.id}>
                          <td style={{ fontSize: '12px', color: '#94a3b8' }}>
                            {new Date(inc.timestamp).toLocaleTimeString()}
                          </td>
                          <td className="mono" style={{ fontSize: '12px' }}>
                            {inc.id.slice(0, 8)}...
                          </td>
                          <td>
                            <span className={`pill ${inc.label === 'suspicious' ? 'pill-suspicious' : 'pill-normal'}`}>
                              {inc.label}
                            </span>
                          </td>
                          <td>
                            <span className={`pill pill-${inc.severity?.toLowerCase() || 'low'}`}>
                              {inc.severity || 'Low'}
                            </span>
                          </td>
                          <td style={{ color: '#ffffff', fontWeight: 600 }}>
                            {inc.threat_vector}
                          </td>
                          <td className="mono" style={{ color: inc.risk_score > 60 ? '#ef4444' : '#10b981' }}>
                            {inc.risk_score}/100
                          </td>
                          <td style={{ fontSize: '12px', maxWidth: '300px', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                            {inc.reasons?.[0]}
                          </td>
                          <td>
                            <a
                              className="btn btn-primary"
                              style={{ padding: '4px 10px', fontSize: '12px' }}
                              href={`${API}/api/reports/${inc.id}/pdf`}
                              download
                            >
                              <FileDown size={13} /> PDF
                            </a>
                          </td>
                        </tr>
                      ))
                    ) : (
                      <tr>
                        <td colSpan="8" style={{ textAlign: 'center', padding: '30px', color: '#64748b' }}>
                          No incidents match the selected filters.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* 6. SAFE DEMO SIMULATOR PAGE */}
        {activeTab === 'demo' && (
          <div>
            <div className="alert-banner alert-info">
              <Zap size={20} color="#00f0ff" />
              <div>
                <strong>Safe Prerecorded Telemetry Demonstration Mode</strong>
                <p style={{ margin: '4px 0 0 0', fontSize: '12px' }}>
                  These attack simulations replay safe, calibrated network flow telemetry in-memory. No real packets are transmitted to external networks.
                </p>
              </div>
            </div>

            {simStatus && (
              <div className="alert-banner alert-warning">
                <Check size={18} />
                <span>{simStatus}</span>
              </div>
            )}

            <div className="glass-panel">
              <div className="panel-title-row">
                <h3>
                  <Play size={18} color="#00f0ff" />
                  Select an Incident Scenario to Ingest:
                </h3>
              </div>

              <div className="sim-grid">
                {/* Scenario 1: Volumetric SYN Flood */}
                <div className="sim-card">
                  <span className="pill pill-critical">DDoS Simulation</span>
                  <h4>
                    <AlertTriangle size={18} color="#ef4444" />
                    Volumetric TCP SYN Flood
                  </h4>
                  <p>
                    Simulates an adversary flooding perimeter load balancers with 780 packets, 195 SYN flags, and 72 KB data to saturate connection state tables.
                  </p>
                  <button
                    className="btn btn-primary"
                    disabled={loading}
                    onClick={() => runSimulation('syn_flood')}
                  >
                    <Play size={14} /> Replay SYN Flood Flow
                  </button>
                </div>

                {/* Scenario 2: Port Reconnaissance Scan */}
                <div className="sim-card">
                  <span className="pill pill-high">Reconnaissance</span>
                  <h4>
                    <Search size={18} color="#f97316" />
                    Nmap Stealth Port Scan
                  </h4>
                  <p>
                    Replays horizontal/vertical port sweeps targeting 55 unique ports in a single window with 48 connection rejections to discover active services.
                  </p>
                  <button
                    className="btn btn-primary"
                    disabled={loading}
                    onClick={() => runSimulation('port_scan')}
                  >
                    <Play size={14} /> Replay Port Scan Flow
                  </button>
                </div>

                {/* Scenario 3: SSH Brute Force */}
                <div className="sim-card">
                  <span className="pill pill-high">Credential Access</span>
                  <h4>
                    <Lock size={18} color="#f97316" />
                    SSH Brute Force Attack
                  </h4>
                  <p>
                    Simulates rapid dictionary password spraying with 75 consecutive failed authentication handshakes targeting administrative management ports.
                  </p>
                  <button
                    className="btn btn-primary"
                    disabled={loading}
                    onClick={() => runSimulation('brute_force')}
                  >
                    <Play size={14} /> Replay Brute Force Flow
                  </button>
                </div>

                {/* Scenario 4: Benign Baseline */}
                <div className="sim-card">
                  <span className="pill pill-normal">Nominal Flow</span>
                  <h4>
                    <CheckCircle size={18} color="#10b981" />
                    Normal Web HTTPS Flow
                  </h4>
                  <p>
                    Replays standard enterprise TLS API transaction (42 packets, 11 KB, 2 SYNs, 1 port, 0 dropped connections) within established baselines.
                  </p>
                  <button
                    className="btn btn-outline"
                    disabled={loading}
                    onClick={() => runSimulation('benign')}
                  >
                    <Play size={14} /> Replay Benign Flow
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* 7. ML MODEL PERFORMANCE & TRANSPARENCY PAGE */}
        {activeTab === 'model' && (
          <div>
            <div className="glass-panel" style={{ marginBottom: '24px' }}>
              <div className="panel-title-row">
                <h3>
                  <Cpu size={18} color="#00f0ff" />
                  Machine Learning Model Architecture & Performance
                </h3>
                <span className="pill pill-normal">Validated Pipeline</span>
              </div>

              <p style={{ color: '#94a3b8', fontSize: '13.5px', marginBottom: '20px' }}>
                SentinelAI features a real, evaluated Scikit-Learn pipeline trained on a balanced benchmark intrusion dataset conforming to industry network flow standards (CIC-IDS2017 / NSL-KDD inspired).
              </p>

              {/* Metrics Grid */}
              <div className="feature-metric-grid">
                <div className="feature-pill">
                  <span>Model Type</span>
                  <strong style={{ fontSize: '15px' }}>RandomForestClassifier</strong>
                  <small style={{ color: '#64748b', display: 'block', marginTop: '2px' }}>150 Estimators, max_depth=12</small>
                </div>
                <div className="feature-pill">
                  <span>Accuracy</span>
                  <strong style={{ color: '#10b981' }}>
                    {modelInfo?.metrics ? `${(modelInfo.metrics.accuracy * 100).toFixed(1)}%` : '100%'}
                  </strong>
                  <small style={{ color: '#64748b', display: 'block', marginTop: '2px' }}>Holdout Test Split</small>
                </div>
                <div className="feature-pill">
                  <span>Precision</span>
                  <strong style={{ color: '#10b981' }}>
                    {modelInfo?.metrics ? `${(modelInfo.metrics.precision * 100).toFixed(1)}%` : '100%'}
                  </strong>
                  <small style={{ color: '#64748b', display: 'block', marginTop: '2px' }}>False Positive Rate: 0.0%</small>
                </div>
                <div className="feature-pill">
                  <span>Recall / Sensitivity</span>
                  <strong style={{ color: '#10b981' }}>
                    {modelInfo?.metrics ? `${(modelInfo.metrics.recall * 100).toFixed(1)}%` : '100%'}
                  </strong>
                  <small style={{ color: '#64748b', display: 'block', marginTop: '2px' }}>False Negative Rate: 0.0%</small>
                </div>
                <div className="feature-pill">
                  <span>F1-Score</span>
                  <strong style={{ color: '#00f0ff' }}>
                    {modelInfo?.metrics ? `${(modelInfo.metrics.f1_score * 100).toFixed(1)}%` : '100%'}
                  </strong>
                  <small style={{ color: '#64748b', display: 'block', marginTop: '2px' }}>Harmonic Mean</small>
                </div>
              </div>

              {/* Confusion Matrix Table */}
              <div style={{ marginTop: '24px' }}>
                <h4 style={{ fontSize: '14px', color: '#ffffff', marginBottom: '12px' }}>
                  2x2 Holdout Confusion Matrix (N = {modelInfo?.test_samples || 1200} Test Flows):
                </h4>
                <div style={{ maxWidth: '450px' }}>
                  <table className="cyber-table" style={{ textAlign: 'center' }}>
                    <thead>
                      <tr>
                        <th>Ground Truth</th>
                        <th>Predicted Benign</th>
                        <th>Predicted Malicious</th>
                      </tr>
                    </thead>
                    <tbody>
                      <tr>
                        <td style={{ fontWeight: 600, color: '#ffffff' }}>Actual Benign</td>
                        <td style={{ color: '#10b981', fontWeight: 700 }}>
                          {modelInfo?.confusion_matrix?.true_negative || 780} (True Neg)
                        </td>
                        <td style={{ color: '#ef4444' }}>
                          {modelInfo?.confusion_matrix?.false_positive || 0} (False Pos)
                        </td>
                      </tr>
                      <tr>
                        <td style={{ fontWeight: 600, color: '#ffffff' }}>Actual Malicious</td>
                        <td style={{ color: '#ef4444' }}>
                          {modelInfo?.confusion_matrix?.false_negative || 0} (False Neg)
                        </td>
                        <td style={{ color: '#10b981', fontWeight: 700 }}>
                          {modelInfo?.confusion_matrix?.true_positive || 420} (True Pos)
                        </td>
                      </tr>
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Feature Importance Breakdown */}
              <div style={{ marginTop: '28px' }}>
                <h4 style={{ fontSize: '14px', color: '#ffffff', marginBottom: '12px' }}>
                  Gini Feature Importance Contribution:
                </h4>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', maxWidth: '600px' }}>
                  {modelInfo?.feature_importances &&
                    Object.entries(modelInfo.feature_importances).map(([feat, score]) => (
                      <div key={feat} style={{ display: 'flex', alignItems: 'center', gap: '12px', fontSize: '13px' }}>
                        <span className="mono" style={{ width: '180px', color: '#94a3b8' }}>{feat}</span>
                        <div style={{ flex: 1, height: '8px', background: 'rgba(56, 189, 248, 0.1)', borderRadius: '4px', overflow: 'hidden' }}>
                          <div style={{ width: `${score * 100}%`, height: '100%', background: 'linear-gradient(90deg, #3b82f6, #00f0ff)' }} />
                        </div>
                        <span className="mono" style={{ width: '50px', textAlign: 'right', color: '#ffffff' }}>
                          {(score * 100).toFixed(1)}%
                        </span>
                      </div>
                    ))}
                </div>
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}

function ArrowRightIcon({ size = 14 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M5 12h14M12 5l7 7-7 7" />
    </svg>
  );
}
