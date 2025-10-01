# Use minimal base image
FROM alpine:latest

# Install runtime dependencies
RUN apk --no-cache add ca-certificates iputils

# Create non-root user
RUN addgroup -g 1000 -S namealive && \
    adduser -u 1000 -S namealive -G namealive

# Copy pre-built binary (GoReleaser provides this)
COPY namealive /usr/local/bin/namealive

# Set capabilities for ICMP ping
RUN setcap cap_net_raw+ep /usr/local/bin/namealive

# Switch to non-root user
USER namealive

# Set entrypoint
ENTRYPOINT ["/usr/local/bin/namealive"]

# Default command (can be overridden)
CMD ["--help"]