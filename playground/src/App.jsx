import { useState, useEffect } from 'react'
import Header from './components/Header'
import Tabs from './components/Tabs'
import Scanner from './components/Scanner'
import Validator from './components/Validator'
import StatusBar from './components/StatusBar'
import { useSpotter } from './hooks/useSpotter'
import './App.css'

function App() {
  const [activeTab, setActiveTab] = useState('scanner')
  const { spotterReady, status, initSpotter, scanManifest, validateRules } = useSpotter()

  useEffect(() => {
    initSpotter()
  }, [])

  return (
    <div className="app">
      <Header />
      <StatusBar status={status} />
      <Tabs activeTab={activeTab} onTabChange={setActiveTab} />
      
      <div className="main-content">
        <div className="editor-area">
          {activeTab === 'scanner' && (
            <Scanner 
              onScan={scanManifest} 
              disabled={!spotterReady} 
            />
          )}
          {activeTab === 'validator' && (
            <Validator 
              onValidate={validateRules} 
              disabled={!spotterReady} 
            />
          )}
        </div>
      </div>
    </div>
  )
}

export default App
