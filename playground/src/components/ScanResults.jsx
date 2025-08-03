import { useState } from 'react'
import './ScanResults.css'

function ScanResults({ results }) {
  const [expandedFindings, setExpandedFindings] = useState(new Set())

  if (!results || typeof results === 'string') {
    return <div className="output-panel">{results || 'Results will appear here...'}</div>
  }

  const toggleFinding = (index) => {
    const newExpanded = new Set(expandedFindings)
    if (newExpanded.has(index)) {
      newExpanded.delete(index)
    } else {
      newExpanded.add(index)
    }
    setExpandedFindings(newExpanded)
  }

  const getSeverityColor = (severity) => {
    switch (severity?.toLowerCase()) {
      case 'critical': return '#dc2626'
      case 'high': return '#ea580c'
      case 'medium': return '#d97706'
      case 'low': return '#65a30d'
      default: return '#6b7280'
    }
  }

  const getSeverityIcon = (severity) => {
    switch (severity?.toLowerCase()) {
      case 'critical': return '🔴'
      case 'high': return '🟠'
      case 'medium': return '🟡'
      case 'low': return '🟢'
      default: return '⚪'
    }
  }

  return (
    <div className="scan-results">
      {/* Summary Section */}
      <div className="results-summary">
        <h3>Scan Summary</h3>
        <div className="summary-stats">
          <div className="stat-item">
            <span className="stat-label">Total Issues:</span>
            <span className="stat-value">{results.summary?.total || 0}</span>
          </div>
          <div className="stat-item">
            <span className="stat-label">Rules Applied:</span>
            <span className="stat-value">{results.selectedRules || 0}</span>
          </div>
          <div className="stat-item">
            <span className="stat-label">Scan Type:</span>
            <span className="stat-value">{results.scanType || 'Unknown'}</span>
          </div>
        </div>
        
        {results.summary && (
          <div className="severity-breakdown">
            {results.summary.critical > 0 && (
              <div className="severity-badge critical">
                🔴 Critical: {results.summary.critical}
              </div>
            )}
            {results.summary.high > 0 && (
              <div className="severity-badge high">
                🟠 High: {results.summary.high}
              </div>
            )}
            {results.summary.medium > 0 && (
              <div className="severity-badge medium">
                🟡 Medium: {results.summary.medium}
              </div>
            )}
            {results.summary.low > 0 && (
              <div className="severity-badge low">
                🟢 Low: {results.summary.low}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Findings Section */}
      {results.findings && results.findings.length > 0 ? (
        <div className="findings-section">
          <h3>Security Findings</h3>
          <div className="findings-list">
            {results.findings.map((finding, index) => (
              <div key={index} className="finding-item">
                <div 
                  className="finding-header"
                  onClick={() => toggleFinding(index)}
                  style={{ cursor: 'pointer' }}
                >
                  <div className="finding-title">
                    <span className="severity-icon">
                      {getSeverityIcon(finding.severity)}
                    </span>
                    <span className="rule-name">{finding.rule}</span>
                    <span 
                      className="severity-label"
                      style={{ color: getSeverityColor(finding.severity) }}
                    >
                      {finding.severity?.toUpperCase()}
                    </span>
                  </div>
                  <div className="resource-info">
                    <span className="resource-name">{finding.resource}</span>
                    {finding.namespace && (
                      <span className="namespace">({finding.namespace})</span>
                    )}
                  </div>
                  <div className="expand-icon">
                    {expandedFindings.has(index) ? '▼' : '▶'}
                  </div>
                </div>
                
                {expandedFindings.has(index) && (
                  <div className="finding-details">
                    <div className="detail-row">
                      <strong>Message:</strong>
                      <span>{finding.message}</span>
                    </div>
                    {finding.remediation && (
                      <div className="detail-row">
                        <strong>Remediation:</strong>
                        <span className="remediation">{finding.remediation}</span>
                      </div>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      ) : (
        <div className="no-findings">
          <div className="success-message">
            ✅ No security issues found! Your manifest looks good.
          </div>
        </div>
      )}
    </div>
  )
}

export default ScanResults