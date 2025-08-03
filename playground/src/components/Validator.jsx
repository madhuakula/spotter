import { useState } from 'react'
import MonacoEditor from './MonacoEditor'

const defaultRules = `apiVersion: spotter.security/v1
kind: SecurityRule
metadata:
  name: example-rule
spec:
  title: "Example Security Rule"
  description: "An example rule for demonstration"
  severity: medium
  category: security
  expression: |
    has(object.spec.securityContext) && 
    object.spec.securityContext.privileged == true`

function Validator({ onValidate, disabled }) {
  const [rulesInput, setRulesInput] = useState(defaultRules)
  const [rulesOutput, setRulesOutput] = useState('Results will appear here...')

  const handleValidate = async () => {
    if (!rulesInput.trim()) {
      setRulesOutput('Please enter security rules to validate.')
      return
    }

    setRulesOutput('Validating...')
    
    try {
      const result = await onValidate(rulesInput)
      setRulesOutput(JSON.stringify(result, null, 2))
    } catch (error) {
      setRulesOutput(`Validation failed: ${error.message || error}`)
    }
  }

  const clearOutput = () => {
    setRulesOutput('Results will appear here...')
  }

  return (
    <>
      <div className="editor-section">
        <div className="section-title">
          <div className="file-icon">V</div>
          Security Rules
        </div>
        <MonacoEditor
          value={rulesInput}
          onChange={setRulesInput}
          language="yaml"
          placeholder="# Paste your security rules here..."
          height="300px"
          disabled={disabled}
        />
        
        <div className="toolbar">
          <button 
            className="btn" 
            onClick={handleValidate} 
            disabled={disabled}
          >
            Validate Rules
          </button>
          <button className="btn btn-secondary" onClick={clearOutput}>
            Clear Output
          </button>
        </div>
      </div>

      <div className="editor-section">
        <div className="section-title">Validation Results</div>
        <div className="output-panel">{rulesOutput}</div>
      </div>
    </>
  )
}

export default Validator