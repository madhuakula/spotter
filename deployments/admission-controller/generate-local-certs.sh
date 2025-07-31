#!/bin/bash

# Simple certificate generation for local testing
set -e

NAMESPACE="spotter-system"
SERVICE_NAME="spotter-admission-controller"
SECRET_NAME="spotter-admission-controller-certs"

echo "🔐 Generating certificates..."

# Generate CA key and certificate
openssl genrsa -out ca.key 2048 2>/dev/null
openssl req -new -x509 -days 365 -key ca.key -out ca.crt -subj "/CN=Local-CA" 2>/dev/null

# Generate server key
openssl genrsa -out server.key 2048 2>/dev/null

# Generate server certificate
openssl req -new -key server.key -out server.csr -subj "/CN=${SERVICE_NAME}.${NAMESPACE}.svc" 2>/dev/null
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365 \
  -extensions v3_req -extfile <(echo "[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:${SERVICE_NAME}.${NAMESPACE}.svc") 2>/dev/null

echo "✅ Certificates generated"

# Create namespace and secret
kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
kubectl create secret tls "$SECRET_NAME" --cert=server.crt --key=server.key --namespace="$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -

# Update webhook with CA bundle  
CA_BUNDLE=$(base64 -w 0 < ca.crt)
if [ -f "local-webhook.yaml" ]; then
    # Update CA bundle in-place without creating backup files
    sed -i "s|caBundle:.*|caBundle: $CA_BUNDLE|g" local-webhook.yaml
    echo "✅ Updated webhook with CA bundle"
fi

# Cleanup
rm -f ca.key ca.crt server.key server.crt server.csr ca.srl

echo "✅ Setup complete!"
