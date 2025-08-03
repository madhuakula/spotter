# Spotter WASM Playground

A React-Vite application for testing Spotter WebAssembly functionality with a VS Code-like interface.

## Features

- **Dark Theme**: Professional code editor appearance
- **Tabbed Interface**: Switch between Kubernetes manifest scanner and security rule validator
- **File Explorer**: VS Code-style sidebar with project structure
- **Real-time WASM Integration**: Direct integration with Spotter WebAssembly module

## Getting Started

1. Install dependencies:
   ```bash
   npm install
   ```

2. Place your `spotter.wasm` file in the `public/` directory

3. Start the development server:
   ```bash
   npm run dev
   ```

4. Open your browser to the displayed URL (usually `http://localhost:5173`)

## Project Structure

```
playground/
├── public/
│   ├── spotter.wasm      # Spotter WebAssembly module
│   └── wasm_exec.js      # Go WASM runtime
├── src/
│   ├── components/       # React components
│   │   ├── Header.jsx    # Top header bar
│   │   ├── Tabs.jsx      # File tabs
│   │   ├── Sidebar.jsx   # File explorer sidebar
│   │   ├── Scanner.jsx   # Kubernetes manifest scanner
│   │   ├── Validator.jsx # Security rules validator
│   │   └── StatusBar.jsx # Status indicator
│   ├── hooks/
│   │   └── useSpotter.js # Custom hook for WASM integration
│   └── App.jsx           # Main application component
└── package.json
```

## Usage

### Manifest Scanner
1. Click on the "manifest.yaml" tab
2. Paste your Kubernetes YAML manifest in the editor
3. Click "Run Security Scan" to analyze the manifest
4. View results in the output panel

### Rule Validator
1. Click on the "rules.yaml" tab
2. Paste your security rules in the editor
3. Click "Validate Rules" to check rule syntax
4. View validation results in the output panel

## Development

- `npm run dev` - Start development server
- `npm run build` - Build for production
- `npm run preview` - Preview production build
- `npm run lint` - Run ESLint

## Notes

- The WASM module must be placed in the `public/` directory to be accessible
- The Go WASM runtime (`wasm_exec.js`) is required for WebAssembly execution
- The interface mimics VS Code's dark theme for a familiar developer experience