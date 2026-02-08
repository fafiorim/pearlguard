FROM clamav/clamav:latest

# Update virus database on build
RUN freshclam

# Expose ClamAV daemon port
EXPOSE 3310

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=120s --retries=3 \
  CMD clamdcheck || exit 1

# Start ClamAV daemon
CMD ["clamd"]
