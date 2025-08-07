import { useState } from 'react'
import RuleSelector from './RuleSelector'
import MonacoEditor from './MonacoEditor'
import ScanResults from './ScanResults'

const defaultManifest = `apiVersion: v1
kind: Pod
metadata:
  name: example-pod
  namespace: default
spec:
  containers:
  - name: app
    image: nginx:latest
    securityContext:
      runAsRoot: true
      privileged: true
    resources: {}`

function Scanner({ onScan, disabled }) {
  const [manifestInput, setManifestInput] = useState(defaultManifest)
  const [scanResults, setScanResults] = useState(null)
  const [isScanning, setIsScanning] = useState(false)
  const [selectedRules, setSelectedRules] = useState([])

  const handleScan = async () => {
    if (!manifestInput.trim()) {
      setScanResults('Please enter a Kubernetes manifest to scan.')
      return
    }

    setIsScanning(true)
    setScanResults('Scanning...')
    
    try {
      const result = await onScan(manifestInput, { selectedRules })
      setScanResults(result)
    } catch (error) {
      setScanResults(`Scan failed: ${error.message || error}`)
    } finally {
      setIsScanning(false)
    }
  }

  const clearOutput = () => {
    setScanResults(null)
  }

  return (
    <div style={{ display: 'flex', gap: '24px', height: '100%' }}>
      <div style={{ width: '300px', flexShrink: 0 }}>
        <RuleSelector 
          onRulesChange={setSelectedRules}
          disabled={disabled}
        />
      </div>
      
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden auto', paddingRight: '4px' }}>
        <div className="editor-section">
          <div className="section-title">
            <div className="file-icon">K</div>
            Kubernetes Manifest
          </div>
          <MonacoEditor
            value={manifestInput}
            onChange={setManifestInput}
            language="yaml"
            placeholder="# Paste your Kubernetes YAML manifest here..."
            height="300px"
            disabled={disabled}
          />
          
          <div className="toolbar">
            <button 
              className="btn" 
              onClick={handleScan} 
              disabled={disabled || isScanning}
            >
              {isScanning ? 'Scanning...' : 'Run Security Scan'}
            </button>
            <button className="btn btn-secondary" onClick={clearOutput}>
              Clear Output
            </button>
          </div>
        </div>

        <div className="editor-section">
          <div className="section-title">Scan Results</div>
          <ScanResults results={scanResults} />
        </div>
      </div>
    </div>
  )
}

export default Scanner