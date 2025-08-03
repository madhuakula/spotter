import { useState, useEffect } from 'react'
import './RuleSelector.css'

function RuleSelector({ onRulesChange, disabled }) {
  const [rules, setRules] = useState([])
  const [categories, setCategories] = useState({})
  const [selectedRules, setSelectedRules] = useState(new Set())
  const [expandedCategories, setExpandedCategories] = useState(new Set())
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    if (disabled) return
    loadRules()
  }, [disabled])

  const loadRules = async () => {
    try {
      setLoading(true)
      setError(null)
      
      if (!window.spotter || !window.spotter.getRules) {
        throw new Error('Spotter WASM module not loaded')
      }

      const result = await window.spotter.getRules()
      setRules(result.rules || [])
      setCategories(result.categories || {})
      
      // Select all rules by default
      const allRuleIds = new Set(result.rules.map(rule => rule.id))
      setSelectedRules(allRuleIds)
      onRulesChange(Array.from(allRuleIds))
      
      // Expand first category by default
      const firstCategory = Object.keys(result.categories)[0]
      if (firstCategory) {
        setExpandedCategories(new Set([firstCategory]))
      }
      
    } catch (err) {
      setError(err.message)
      console.error('Failed to load rules:', err)
    } finally {
      setLoading(false)
    }
  }

  const toggleRule = (ruleId) => {
    const newSelected = new Set(selectedRules)
    if (newSelected.has(ruleId)) {
      newSelected.delete(ruleId)
    } else {
      newSelected.add(ruleId)
    }
    setSelectedRules(newSelected)
    onRulesChange(Array.from(newSelected))
  }

  const toggleCategory = (category) => {
    const categoryRules = categories[category] || []
    const categoryRuleIds = categoryRules.map(rule => rule.id)
    const allSelected = categoryRuleIds.every(id => selectedRules.has(id))
    
    const newSelected = new Set(selectedRules)
    if (allSelected) {
      // Deselect all rules in category
      categoryRuleIds.forEach(id => newSelected.delete(id))
    } else {
      // Select all rules in category
      categoryRuleIds.forEach(id => newSelected.add(id))
    }
    
    setSelectedRules(newSelected)
    onRulesChange(Array.from(newSelected))
  }

  const toggleCategoryExpansion = (category) => {
    const newExpanded = new Set(expandedCategories)
    if (newExpanded.has(category)) {
      newExpanded.delete(category)
    } else {
      newExpanded.add(category)
    }
    setExpandedCategories(newExpanded)
  }

  const selectAll = () => {
    const allRuleIds = new Set(rules.map(rule => rule.id))
    setSelectedRules(allRuleIds)
    onRulesChange(Array.from(allRuleIds))
  }

  const selectNone = () => {
    setSelectedRules(new Set())
    onRulesChange([])
  }

  const getSeverityClass = (severity) => {
    switch (severity?.toLowerCase()) {
      case 'critical': return 'severity-critical'
      case 'high': return 'severity-high'
      case 'medium': return 'severity-medium'
      case 'low': return 'severity-low'
      default: return 'severity-medium'
    }
  }

  if (loading) {
    return (
      <div className="rule-selector">
        <div className="rule-selector-header">
          <h3>Security Rules</h3>
        </div>
        <div className="loading">Loading rules...</div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="rule-selector">
        <div className="rule-selector-header">
          <h3>Security Rules</h3>
        </div>
        <div className="error">
          <p>Failed to load rules: {error}</p>
          <button className="btn btn-small" onClick={loadRules}>
            Retry
          </button>
        </div>
      </div>
    )
  }

  return (
    <div className="rule-selector">
      <div className="rule-selector-header">
        <h3>Security Rules</h3>
        <div className="rule-stats">
          {selectedRules.size} of {rules.length} selected
        </div>
      </div>
      
      <div className="rule-actions">
        <button 
          className="btn btn-small" 
          onClick={selectAll}
          disabled={disabled}
        >
          Select All
        </button>
        <button 
          className="btn btn-small btn-secondary" 
          onClick={selectNone}
          disabled={disabled}
        >
          Select None
        </button>
      </div>

      <div className="rule-categories">
        {Object.entries(categories).map(([category, categoryRules]) => {
          const isExpanded = expandedCategories.has(category)
          const selectedCount = categoryRules.filter(rule => selectedRules.has(rule.id)).length
          const totalCount = categoryRules.length
          const allSelected = selectedCount === totalCount
          const someSelected = selectedCount > 0 && selectedCount < totalCount
          
          return (
            <div key={category} className="rule-category">
              <div className="category-header">
                <button
                  className="category-toggle"
                  onClick={() => toggleCategoryExpansion(category)}
                  disabled={disabled}
                >
                  <span className={`expand-icon ${isExpanded ? 'expanded' : ''}`}>
                    ▶
                  </span>
                </button>
                
                <label className="category-checkbox">
                  <input
                    type="checkbox"
                    checked={allSelected}
                    ref={input => {
                      if (input) input.indeterminate = someSelected
                    }}
                    onChange={() => toggleCategory(category)}
                    disabled={disabled}
                  />
                  <span className="category-name">{category}</span>
                  <span className="category-count">({selectedCount}/{totalCount})</span>
                </label>
              </div>
              
              {isExpanded && (
                <div className="category-rules">
                  {categoryRules.map(rule => (
                    <label key={rule.id} className="rule-item">
                      <input
                        type="checkbox"
                        checked={selectedRules.has(rule.id)}
                        onChange={() => toggleRule(rule.id)}
                        disabled={disabled}
                      />
                      <div className="rule-info">
                        <div className="rule-header">
                          <span className="rule-name">{rule.name}</span>
                          <span className={`severity-badge ${getSeverityClass(rule.severity)}`}>
                            {rule.severity}
                          </span>
                        </div>
                        <div className="rule-description">{rule.description}</div>
                        {rule.subcategory && (
                          <div className="rule-subcategory">{rule.subcategory}</div>
                        )}
                      </div>
                    </label>
                  ))}
                </div>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}

export default RuleSelector