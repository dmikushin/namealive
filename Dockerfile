# Multi-stage build for minimal image size
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git make

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags="-s -w" -o namealive .

# Final stage
FROM alpine:latest

# Install runtime dependencies
RUN apk --no-cache add ca-certificates iputils

# Create non-root user
RUN addgroup -g 1000 -S namealive && \
    adduser -u 1000 -S namealive -G namealive

# Copy binary from builder
COPY --from=builder /app/namealive /usr/local/bin/namealive

# Set capabilities for ICMP ping
RUN setcap cap_net_raw+ep /usr/local/bin/namealive

# Switch to non-root user
USER namealive

# Set entrypoint
ENTRYPOINT ["/usr/local/bin/namealive"]

# Default command (can be overridden)
CMD ["--help"]