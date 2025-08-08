# Build stage
FROM golang:1.24-alpine AS builder

# Build arguments to control build behavior
ARG ENABLE_VERSIONING=true
ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY *.go ./
COPY cmd/ cmd/
COPY pkg/ pkg/
COPY internal/ internal/

# Build the application with conditional ldflags
RUN if [ "$ENABLE_VERSIONING" = "true" ]; then \
        CGO_ENABLED=0 GOOS=linux go build \
        -ldflags="-s -w -X github.com/madhuakula/spotter/pkg/version.Version=${VERSION} \
        -X github.com/madhuakula/spotter/pkg/version.Commit=${COMMIT} \
        -X github.com/madhuakula/spotter/pkg/version.Date=${DATE}" \
        -o spotter .; \
    else \
        CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags='-w -s' -o spotter .; \
    fi

# Final image (distroless for security and versatility)
FROM gcr.io/distroless/static:nonroot

# Copy ca-certificates from builder (already included in distroless)
# Copy timezone data from builder (already included in distroless)

# Copy binary from builder stage
COPY --from=builder /app/spotter /spotter

# Use non-root user (distroless nonroot user is 65532)
USER 65532:65532

# Expose the admission controller port (useful when running as server)
EXPOSE 8443

# Set entrypoint
ENTRYPOINT ["/spotter"]

# Default command (help)
CMD ["--help"]
