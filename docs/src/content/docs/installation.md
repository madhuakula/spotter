---
title: Installation
description: Install Spotter using various methods
---

Spotter can be installed using multiple methods to suit different environments and preferences. Choose the method that works best for your setup.

## Installation Methods

### 1. Go Install (Recommended)

If you have Go installed, this is the quickest way to get the latest version:

```bash
go install github.com/madhuakula/spotter@latest
```

Verify the installation:

```bash
spotter version
```

### 2. Download Binary

Download pre-compiled binaries from the [GitHub Releases](https://github.com/madhuakula/spotter/releases) page.

#### Linux (x86_64)

```bash
# Download the latest release
wget https://github.com/madhuakula/spotter/releases/latest/download/spotter-linux-amd64.tar.gz

# Extract and install
tar -xzf spotter-linux-amd64.tar.gz
sudo mv spotter /usr/local/bin/

# Verify installation
spotter version
```

#### macOS (Intel)

```bash
# Download the latest release
wget https://github.com/madhuakula/spotter/releases/latest/download/spotter-darwin-amd64.tar.gz

# Extract and install
tar -xzf spotter-darwin-amd64.tar.gz
sudo mv spotter /usr/local/bin/

# Verify installation
spotter version
```

#### macOS (Apple Silicon)

```bash
# Download the latest release
wget https://github.com/madhuakula/spotter/releases/latest/download/spotter-darwin-arm64.tar.gz

# Extract and install
tar -xzf spotter-darwin-arm64.tar.gz
sudo mv spotter /usr/local/bin/

# Verify installation
spotter version
```

#### Windows

1. Download `spotter-windows-amd64.zip` from the [releases page](https://github.com/madhuakula/spotter/releases)
2. Extract the ZIP file
3. Add the extracted directory to your PATH environment variable
4. Open a new command prompt and verify: `spotter version`

### 3. Docker

Run Spotter using Docker without installing it locally:

```bash
# Pull the latest image
docker pull madhuakula/spotter:latest

# Run Spotter (example: scan manifests)
docker run --rm -v $(pwd):/workspace madhuakula/spotter:latest scan manifests /workspace

# For cluster scanning, mount kubeconfig
docker run --rm -v ~/.kube:/root/.kube madhuakula/spotter:latest scan cluster
```

#### Docker Compose

Create a `docker-compose.yml` file:

```yaml
version: '3.8'
services:
  spotter:
    image: madhuakula/spotter:latest
    volumes:
      - ~/.kube:/root/.kube:ro
      - ./manifests:/workspace:ro
    command: ["scan", "manifests", "/workspace"]
```

Run with:

```bash
docker-compose run --rm spotter
```

### 4. Build from Source

For the latest development version or custom builds:

```bash
# Clone the repository
git clone https://github.com/madhuakula/spotter.git
cd spotter

# Build the binary
make build

# Install to system PATH
sudo cp bin/spotter /usr/local/bin/

# Verify installation
spotter version
```

## Kubernetes RBAC Setup

For cluster scanning, Spotter needs appropriate permissions. Create the following RBAC resources:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: spotter
  namespace: default
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: spotter-reader
rules:
- apiGroups: [""]
  resources: ["*"]
  verbs: ["get", "list"]
- apiGroups: ["apps"]
  resources: ["*"]
  verbs: ["get", "list"]
- apiGroups: ["networking.k8s.io"]
  resources: ["*"]
  verbs: ["get", "list"]
- apiGroups: ["policy"]
  resources: ["*"]
  verbs: ["get", "list"]
- apiGroups: ["rbac.authorization.k8s.io"]
  resources: ["*"]
  verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: spotter-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: spotter-reader
subjects:
- kind: ServiceAccount
  name: spotter
  namespace: default
```

Apply the RBAC configuration:

```bash
kubectl apply -f spotter-rbac.yaml
```

## Configuration

Spotter can be configured using:

1. **Command-line flags**: Override specific settings
2. **Configuration file**: Use `spotter.yaml` for persistent settings
3. **Environment variables**: Set `SPOTTER_*` variables

### Basic Configuration File

Create a `spotter.yaml` file:

```yaml
# Spotter Configuration
logging:
  level: info
  format: text

scanner:
  workers: 10
  timeout: 30s

rules:
  builtin:
    enabled: true
  custom:
    paths:
      - "./custom-rules"

output:
  format: table
  file: ""
  no-color: false

kubernetes:
  kubeconfig: ""
  context: ""
  namespace: ""

performance:
  max-concurrent-scans: 50
  rule-cache-size: 1000
```

## Verification

After installation, verify Spotter is working correctly:

```bash
# Check version
spotter version

# List available commands
spotter --help

# Test with a simple manifest scan
echo 'apiVersion: v1
kind: Pod
metadata:
  name: test-pod
spec:
  containers:
  - name: test
    image: nginx
    securityContext:
      privileged: true' | spotter scan manifests -
```

You should see security findings related to the privileged container.

## Next Steps

- **Quick Start**: Try the [Quick Start Guide](/quick-start/) for hands-on examples
- **Configuration**: Learn about [Configuration Options](/configuration/)
- **CLI Usage**: Explore [CLI Commands](/cli/)
- **Security Rules**: Understand [Built-in Rules](/rules/builtin/)

## Troubleshooting

### Common Issues

**Permission Denied (Cluster Scanning)**
```bash
# Check your kubeconfig
kubectl config current-context

# Test cluster access
kubectl get nodes
```

**Binary Not Found**
```bash
# Check if binary is in PATH
which spotter

# Add to PATH if needed (Linux/macOS)
export PATH=$PATH:/usr/local/bin
```

**Docker Permission Issues**
```bash
# Add user to docker group (Linux)
sudo usermod -aG docker $USER

# Restart shell or logout/login
```

For more help, check the [GitHub Issues](https://github.com/madhuakula/spotter/issues) or create a new issue.