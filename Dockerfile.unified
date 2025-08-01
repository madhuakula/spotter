# Build arguments must be declared before first FROM
ARG BUILD_TARGET=cli

# Build stage
FROM golang:1.24-alpine AS builder

# Build arguments to control build behavior
ARG ENABLE_VERSIONING=true

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

# Build the application with conditional ldflags
RUN if [ "$ENABLE_VERSIONING" = "true" ]; then \
        CGO_ENABLED=0 GOOS=linux go build \
        -ldflags="-s -w -X github.com/madhuakula/spotter/pkg/version.Version=$(git describe --tags --always --dirty) \
        -X github.com/madhuakula/spotter/pkg/version.Commit=$(git rev-parse --short HEAD) \
        -X github.com/madhuakula/spotter/pkg/version.Date=$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
        -o spotter .; \
    else \
        CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags='-w -s' -o spotter .; \
    fi

# CLI version (scratch-based for minimal size)
FROM scratch AS cli

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

# Admission controller version (distroless for security)
FROM gcr.io/distroless/static:nonroot AS admission

# Copy binary from builder stage
COPY --from=builder /app/spotter /spotter

# Use non-root user (distroless nonroot user is 65532)
USER 65532:65532

# Expose the admission controller port
EXPOSE 8443

# Set entrypoint
ENTRYPOINT ["/spotter"]

# Default command
CMD ["server", "--mode=validating", "--port=8443"]
