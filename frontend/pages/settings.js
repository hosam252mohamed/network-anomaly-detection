import { useState, useEffect } from 'react'
import Head from 'next/head'
import Sidebar from '../components/Sidebar'

const API_BASE = 'http://localhost:8000'

export default function Settings() {
    const [settings, setSettings] = useState({
        detectionMethod: 'combined',
        zscoreThreshold: 3.0,
        contamination: 0.1,
        alertSeverityThreshold: 2.0,
        autoRefresh: true,
        refreshInterval: 30,
        emailNotifications: false,
        notificationEmail: ''
    })
    const [saved, setSaved] = useState(false)
    const [modelInfo, setModelInfo] = useState(null)

    // Load model status
    useEffect(() => {
        fetch(`${API_BASE}/api/stats`)
            .then(res => res.json())
            .then(data => setModelInfo(data))
            .catch(console.error)
    }, [])

    // Handle changes
    const handleChange = (key, value) => {
        setSettings({ ...settings, [key]: value })
        setSaved(false)
    }

    // Save settings (in real app, this would persist to backend)
    const saveSettings = () => {
        localStorage.setItem('nad_settings', JSON.stringify(settings))
        setSaved(true)
        setTimeout(() => setSaved(false), 3000)
    }

    // Load settings on mount
    useEffect(() => {
        const saved = localStorage.getItem('nad_settings')
        if (saved) {
            setSettings(JSON.parse(saved))
        }
    }, [])

    return (
        <>
            <Head>
                <title>Settings | Network Anomaly Detection</title>
                <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet" />
            </Head>

            <div className="dashboard">
                <Sidebar activePage="settings" />

                <main className="main-content">
                    <div style={{ marginBottom: '2rem' }}>
                        <h1>Settings</h1>
                        <p style={{ marginTop: '0.5rem' }}>Configure detection parameters and preferences</p>
                    </div>

                    {/* Detection Settings */}
                    <div className="card" style={{ marginBottom: '1.5rem' }}>
                        <div className="card-header">
                            <span className="card-title">🔍 Detection Settings</span>
                        </div>

                        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '1.5rem' }}>
                            {/* Detection Method */}
                            <div>
                                <label style={{ display: 'block', marginBottom: '0.5rem', fontSize: '0.875rem', color: 'var(--text-secondary)' }}>
                                    Default Detection Method
                                </label>
                                <select
                                    value={settings.detectionMethod}
                                    onChange={(e) => handleChange('detectionMethod', e.target.value)}
                                    style={{
                                        width: '100%',
                                        padding: '0.75rem',
                                        background: 'var(--bg-secondary)',
                                        border: '1px solid var(--border-color)',
                                        borderRadius: 'var(--radius-md)',
                                        color: 'var(--text-primary)'
                                    }}
                                >
                                    <option value="combined">Combined (All Methods)</option>
                                    <option value="statistical">Statistical Only</option>
                                    <option value="isolation_forest">Isolation Forest Only</option>
                                </select>
                            </div>

                            {/* Z-Score Threshold */}
                            <div>
                                <label style={{ display: 'block', marginBottom: '0.5rem', fontSize: '0.875rem', color: 'var(--text-secondary)' }}>
                                    Z-Score Threshold: {settings.zscoreThreshold}
                                </label>
                                <input
                                    type="range"
                                    min="1"
                                    max="5"
                                    step="0.5"
                                    value={settings.zscoreThreshold}
                                    onChange={(e) => handleChange('zscoreThreshold', parseFloat(e.target.value))}
                                    style={{ width: '100%' }}
                                />
                                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                                    <span>More Sensitive</span>
                                    <span>Less Sensitive</span>
                                </div>
                            </div>

                            {/* Contamination */}
                            <div>
                                <label style={{ display: 'block', marginBottom: '0.5rem', fontSize: '0.875rem', color: 'var(--text-secondary)' }}>
                                    Isolation Forest Contamination: {(settings.contamination * 100).toFixed(0)}%
                                </label>
                                <input
                                    type="range"
                                    min="0.01"
                                    max="0.3"
                                    step="0.01"
                                    value={settings.contamination}
                                    onChange={(e) => handleChange('contamination', parseFloat(e.target.value))}
                                    style={{ width: '100%' }}
                                />
                                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                                    <span>1% Anomalies</span>
                                    <span>30% Anomalies</span>
                                </div>
                            </div>

                            {/* Alert Threshold */}
                            <div>
                                <label style={{ display: 'block', marginBottom: '0.5rem', fontSize: '0.875rem', color: 'var(--text-secondary)' }}>
                                    Alert Severity Threshold: {settings.alertSeverityThreshold}
                                </label>
                                <input
                                    type="range"
                                    min="1"
                                    max="5"
                                    step="0.5"
                                    value={settings.alertSeverityThreshold}
                                    onChange={(e) => handleChange('alertSeverityThreshold', parseFloat(e.target.value))}
                                    style={{ width: '100%' }}
                                />
                            </div>
                        </div>
                    </div>

                    {/* Dashboard Settings */}
                    <div className="card" style={{ marginBottom: '1.5rem' }}>
                        <div className="card-header">
                            <span className="card-title">📊 Dashboard Settings</span>
                        </div>

                        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '1.5rem' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                                <input
                                    type="checkbox"
                                    id="autoRefresh"
                                    checked={settings.autoRefresh}
                                    onChange={(e) => handleChange('autoRefresh', e.target.checked)}
                                    style={{ width: '20px', height: '20px' }}
                                />
                                <label htmlFor="autoRefresh">Auto-refresh dashboard data</label>
                            </div>

                            <div>
                                <label style={{ display: 'block', marginBottom: '0.5rem', fontSize: '0.875rem', color: 'var(--text-secondary)' }}>
                                    Refresh Interval (seconds)
                                </label>
                                <input
                                    type="number"
                                    min="10"
                                    max="120"
                                    value={settings.refreshInterval}
                                    onChange={(e) => handleChange('refreshInterval', parseInt(e.target.value))}
                                    disabled={!settings.autoRefresh}
                                    style={{
                                        width: '100%',
                                        padding: '0.75rem',
                                        background: 'var(--bg-secondary)',
                                        border: '1px solid var(--border-color)',
                                        borderRadius: 'var(--radius-md)',
                                        color: 'var(--text-primary)',
                                        opacity: settings.autoRefresh ? 1 : 0.5
                                    }}
                                />
                            </div>
                        </div>
                    </div>

                    {/* Model Information */}
                    <div className="card" style={{ marginBottom: '1.5rem' }}>
                        <div className="card-header">
                            <span className="card-title">🤖 Model Information</span>
                        </div>

                        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '1rem' }}>
                            {modelInfo?.model_status && Object.entries(modelInfo.model_status).map(([name, loaded]) => (
                                <div
                                    key={name}
                                    style={{
                                        display: 'flex',
                                        alignItems: 'center',
                                        justifyContent: 'space-between',
                                        padding: '1rem',
                                        background: 'var(--bg-secondary)',
                                        borderRadius: 'var(--radius-md)'
                                    }}
                                >
                                    <span style={{ textTransform: 'capitalize' }}>{name.replace('_', ' ')}</span>
                                    <span className={`badge ${loaded ? 'badge-success' : 'badge-danger'}`}>
                                        {loaded ? '✓ Loaded' : '✗ Not Loaded'}
                                    </span>
                                </div>
                            ))}
                        </div>
                    </div>

                    {/* About */}
                    <div className="card" style={{ marginBottom: '1.5rem' }}>
                        <div className="card-header">
                            <span className="card-title">ℹ️ About</span>
                        </div>

                        <div style={{ color: 'var(--text-secondary)' }}>
                            <p><strong>Network Anomaly Detection System</strong></p>
                            <p style={{ marginTop: '0.5rem' }}>Version 1.0.0</p>
                            <p style={{ marginTop: '0.5rem' }}>
                                A machine learning-based system for detecting network anomalies and classifying attack types.
                                Built with Isolation Forest, Random Forest, and Statistical methods.
                            </p>
                            <p style={{ marginTop: '1rem' }}>
                                <strong>Dataset:</strong> CICIDS2017<br />
                                <strong>Features:</strong> 15 selected network flow features<br />
                                <strong>Attack Types:</strong> DDoS, Port Scan, Brute Force, Web Attacks, and more
                            </p>
                        </div>
                    </div>

                    {/* Save Button */}
                    <div style={{ display: 'flex', gap: '1rem', alignItems: 'center' }}>
                        <button className="btn btn-primary" onClick={saveSettings}>
                            💾 Save Settings
                        </button>
                        {saved && (
                            <span style={{ color: 'var(--success)' }}>✓ Settings saved!</span>
                        )}
                    </div>

                    {/* Danger Zone */}
                    <div className="card" style={{ marginTop: '2rem', borderColor: 'var(--danger)' }}>
                        <div className="card-header" style={{ borderBottomColor: 'rgba(239, 68, 68, 0.2)' }}>
                            <span className="card-title" style={{ color: 'var(--danger)' }}>⚠️ Danger Zone</span>
                        </div>

                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                            <div>
                                <h4 style={{ margin: '0 0 0.25rem 0' }}>Reset System Data</h4>
                                <p style={{ margin: 0, fontSize: '0.875rem', color: 'var(--text-secondary)' }}>
                                    Clear all statistics, alerts, and active flows. This cannot be undone.
                                </p>
                            </div>
                            <button
                                className="btn btn-danger"
                                onClick={async () => {
                                    if (confirm('Are you sure you want to reset all data?')) {
                                        await fetch(`${API_BASE}/api/reset`, { method: 'POST' })
                                        localStorage.removeItem('simulatedTraffic')
                                        window.location.reload()
                                    }
                                }}
                                style={{ background: 'var(--danger)', color: 'white' }}
                            >
                                🗑️ Reset Data
                            </button>
                        </div>
                    </div>
                </main>
            </div>
        </>
    )
}
