#!/bin/bash

# Script to generate TLS certificates for Spotter admission controller
# This script creates self-signed certificates for development/testing purposes
# For production, use cert-manager or proper CA-signed certificates

set -e

NAMESPACE="spotter-system"
SERVICE_NAME="spotter-admission-controller"
SECRET_NAME="spotter-admission-controller-certs"

echo "Generating TLS certificates for Spotter admission controller..."

# Create temporary directory
TMP_DIR=$(mktemp -d)
cd "$TMP_DIR"

# Generate CA private key
openssl genrsa -out ca.key 2048

# Generate CA certificate
openssl req -new -x509 -days 365 -key ca.key -out ca.crt -subj "/CN=Spotter CA"

# Generate server private key
openssl genrsa -out server.key 2048

# Create certificate signing request
cat > server.conf <<EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = ${SERVICE_NAME}.${NAMESPACE}.svc

[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${SERVICE_NAME}
DNS.2 = ${SERVICE_NAME}.${NAMESPACE}
DNS.3 = ${SERVICE_NAME}.${NAMESPACE}.svc
DNS.4 = ${SERVICE_NAME}.${NAMESPACE}.svc.cluster.local
IP.1 = 127.0.0.1
EOF

# Generate certificate signing request
openssl req -new -key server.key -out server.csr -config server.conf

# Generate server certificate signed by CA
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365 -extensions v3_req -extfile server.conf

echo "Certificates generated successfully!"

# Create namespace if it doesn't exist
kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -

# Create or update secret with certificates
kubectl create secret tls "$SECRET_NAME" \
    --cert=server.crt \
    --key=server.key \
    --namespace="$NAMESPACE" \
    --dry-run=client -o yaml | kubectl apply -f -

# Get CA bundle for webhook configuration
CA_BUNDLE=$(base64 < ca.crt | tr -d '\n')

echo "CA Bundle for webhook configuration:"
echo "$CA_BUNDLE"

# Update webhook configurations with CA bundle
if [ -f "../webhook.yaml" ]; then
    sed -i.bak "s/caBundle: \"\"/caBundle: $CA_BUNDLE/g" ../webhook.yaml
    echo "Updated webhook.yaml with CA bundle"
fi

# Cleanup
cd ..
rm -rf "$TMP_DIR"

echo ""
echo "✅ TLS certificates have been generated and stored in secret: $SECRET_NAME"
echo "✅ CA bundle has been added to webhook configuration"
echo ""
echo "Next steps:"
echo "1. Build and push the Docker image:"
echo "   docker build -f Dockerfile.admission -t your-registry/spotter:latest ."
echo "   docker push your-registry/spotter:latest"
echo ""
echo "2. Update the image in deployment.yaml"
echo ""
echo "3. Deploy the admission controller:"
echo "   kubectl apply -f deployments/admission-controller/"
echo ""
echo "4. Apply the webhook configuration:"
echo "   kubectl apply -f deployments/admission-controller/webhook.yaml"
