import './Tabs.css'

function Tabs({ activeTab, onTabChange }) {
  const tabs = [
    { id: 'scanner', label: 'Scan', icon: 'S' },
    { id: 'validator', label: 'Validate', icon: 'V' }
  ]

  return (
    <div className="tabs">
      {tabs.map(tab => (
        <button
          key={tab.id}
          className={`tab ${activeTab === tab.id ? 'active' : ''}`}
          onClick={() => onTabChange(tab.id)}
        >
          <div className="file-icon">{tab.icon}</div>
          {tab.label}
        </button>
      ))}
    </div>
  )
}

export default Tabs