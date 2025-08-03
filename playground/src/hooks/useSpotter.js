import { useState, useCallback } from 'react'

export function useSpotter() {
  const [spotterReady, setSpotterReady] = useState(false)
  const [status, setStatus] = useState({
    type: 'loading',
    message: 'Loading Spotter module...'
  })

  const initSpotter = useCallback(async () => {
    try {
      // Load the Go WASM runtime
      const go = new window.Go()
      const result = await WebAssembly.instantiateStreaming(
        fetch('/spotter.wasm'),
        go.importObject
      )
      go.run(result.instance)

      // Wait for spotter to be available
      let attempts = 0
      while (!window.spotter && attempts < 50) {
        await new Promise(resolve => setTimeout(resolve, 100))
        attempts++
      }

      if (window.spotter) {
        setSpotterReady(true)
        setStatus({
          type: 'success',
          message: 'Spotter module loaded successfully!'
        })
        console.log('Spotter version:', window.spotter.version())
      } else {
        throw new Error('Spotter module not available after initialization')
      }
    } catch (error) {
      setStatus({
        type: 'error',
        message: `Failed to load Spotter WASM: ${error.message}`
      })
      console.error('WASM initialization error:', error)
    }
  }, [])

  const scanManifest = useCallback(async (input, options = {}) => {
    if (!spotterReady) {
      throw new Error('Spotter is not ready yet. Please wait for initialization to complete.')
    }

    const scanOptions = {
      format: 'json',
      includePassedChecks: false,
      selectedRules: options.selectedRules || [],
      ...options
    }

    const result = await window.spotter.scan('manifests', input, JSON.stringify(scanOptions))

    return result
  }, [spotterReady])

  const validateRules = useCallback(async (input) => {
    if (!spotterReady) {
      throw new Error('Spotter is not ready yet. Please wait for initialization to complete.')
    }

    const result = await window.spotter.validateRules(input)
    return result
  }, [spotterReady])

  return {
    spotterReady,
    status,
    initSpotter,
    scanManifest,
    validateRules
  }
}