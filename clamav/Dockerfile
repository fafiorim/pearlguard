# Use Alpine Linux as base for ARM64 support
FROM alpine:3.19

# Install ClamAV
RUN apk add --no-cache clamav clamav-daemon clamav-libunrar

# Create directories
RUN mkdir -p /var/run/clamav /var/log/clamav /var/lib/clamav && \
    chown -R clamav:clamav /var/run/clamav /var/log/clamav /var/lib/clamav

# Configure ClamAV
RUN sed -i 's/^#LocalSocket .*/LocalSocket \/var\/run\/clamav\/clamd.sock/' /etc/clamav/clamd.conf && \
    sed -i 's/^#TCPSocket .*/TCPSocket 3310/' /etc/clamav/clamd.conf && \
    sed -i 's/^#TCPAddr .*/TCPAddr 0.0.0.0/' /etc/clamav/clamd.conf && \
    sed -i 's/^#Foreground .*/Foreground yes/' /etc/clamav/clamd.conf

# Update virus database
RUN freshclam

# Expose ClamAV daemon port
EXPOSE 3310

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
  CMD clamdscan --ping 1 || exit 1

# Start ClamAV daemon
CMD ["clamd"]
