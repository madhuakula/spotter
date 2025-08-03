#!/bin/bash

# Build script for Spotter WASM

set -e

echo "Building Spotter for WebAssembly..."

# Set environment variables for WASM build
export GOOS=js
export GOARCH=wasm

# Build the WASM binary
go build -tags wasm -o spotter.wasm .

# Copy the WASM support file from Go installation
WASM_EXEC_JS=$(go env GOROOT)/misc/wasm/wasm_exec.js
WASM_EXEC_JS_ALT=$(go env GOROOT)/lib/wasm/wasm_exec.js

if [ -f "$WASM_EXEC_JS" ]; then
    cp "$WASM_EXEC_JS" ./wasm_exec.js
    echo "Copied wasm_exec.js support file"
elif [ -f "$WASM_EXEC_JS_ALT" ]; then
    cp "$WASM_EXEC_JS_ALT" ./wasm_exec.js
    echo "Copied wasm_exec.js support file from alternative location"
else
    echo "Warning: wasm_exec.js not found at $WASM_EXEC_JS or $WASM_EXEC_JS_ALT"
    echo "You may need to manually copy this file from your Go installation"
fi
# Create playground/public folder if it doesn't exist
mkdir -p playground/public

# Move files to playground/public folder
mv spotter.wasm playground/public/
mv wasm_exec.js playground/public/
echo "Moved files to playground/public/"

echo "WASM build complete!"
echo "Files generated:"
echo "  - spotter.wasm (the WebAssembly binary)"
echo "  - wasm_exec.js (Go WASM runtime support)"

echo ""
echo "To use in a web page, include both files and initialize like this:"
echo ""
echo "  <script src=\"wasm_exec.js\"></script>"
echo "  <script>"
echo "    const go = new Go();"
echo "    WebAssembly.instantiateStreaming(fetch('spotter.wasm'), go.importObject)"
echo "      .then((result) => {"
echo "        go.run(result.instance);"
echo "        // Now you can use window.spotter.scan(), etc."
echo "      });"
echo "  </script>"