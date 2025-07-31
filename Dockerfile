# Build stage
FROM golang:1.24-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -X github.com/madhuakula/spotter/pkg/version.Version=$(git describe --tags --always --dirty) \
    -X github.com/madhuakula/spotter/pkg/version.Commit=$(git rev-parse --short HEAD) \
    -X github.com/madhuakula/spotter/pkg/version.Date=$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    -o spotter .

# Final stage
FROM scratch

# Copy ca-certificates from builder
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy timezone data
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# Copy the binary
COPY --from=builder /app/spotter /usr/local/bin/spotter

# Set entrypoint
ENTRYPOINT ["/usr/local/bin/spotter"]

# Default command
CMD ["--help"]