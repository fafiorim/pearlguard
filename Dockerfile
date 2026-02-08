# Builder stage
# Alternative Base Image: Use a GHCR-hosted image instead of Docker Hub
# FROM ghcr.io/recursivebugs/bytevault/golang:1.24-alpine AS scanner-builder
FROM golang:1.24-alpine AS scanner-builder

WORKDIR /build
# Copy Go files
COPY scanner.go s3scanner.go ./
COPY go.mod go.sum ./
# Build the scanner.
RUN go mod download
RUN go build -o scanner

# Final image
# Alternative Base Image: Use a GHCR-hosted image instead of Docker Hub
# FROM ghcr.io/recursivebugs/bytevault/alpine:latest
FROM alpine:3.15

# Set environment variables with defaults
ENV ADMIN_USERNAME=admin \
    ADMIN_PASSWORD=admin123 \
    USER_USERNAME=user \
    USER_PASSWORD=user123 \
    FSS_API_ENDPOINT=antimalware.us-1.cloudone.trendmicro.com:443 \
    FSS_API_KEY="" \
    FSS_CUSTOM_TAGS="" \
    HTTP_PORT=3000 \
    HTTPS_PORT=3443 \
    SECURITY_MODE=logOnly

WORKDIR /app
# Install Node.js and npm
RUN apk add --update nodejs npm

# Install libssl
RUN apk add --no-cache libssl1.1

# HANA DB config file
RUN echo "WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo=" | base64 -d > /tmp/sap4hana.dat

#AppCredential:
RUN echo "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJjaWQiOiI1NzM5NDY1MS01ZjgwLTQ3YjgtOGUyMS0zN2FkZjM5OGRlZmQiLCJjcGlkIjoic3ZwIiwicHBpZCI6ImN1cyIsIml0IjoxNzIyNDQxOTIyLCJldCI6MTc1Mzk3NzkyMSwiaWQiOiJjYmRkYWViMi0zNzNhLTQ5YjYtYjU5Ny03OWE5YzVkYjVlM2YiLCJ0b2tlblVzZSI6ImN1c3RvbWVyIn0.Jqua_uEpVMN3cnW0BVr8nUtey1aBOFTay7sEQOCCPkNgd6fL3O_Er_gyUTPicWupgoDeyd3UBP2enVDiWcepVOe2U0PKDnJbX6q140hkdL005B4t0h3rNjUBkjoizpsxvw8hjaaS3YVliZXZMQ8gLgC3xZ9KIHu2Mcqy6iwiFsMm6MccMAXCx1wbliUUNRIL3uBFQC2iPqiJUgeXDIiqFsXZpeqtya761FxPd69nRAZoYBR9-" > /tmp/token

# Create necessary directories
RUN mkdir -p /app/public /app/uploads /app/middleware /app/certs && \
    chmod 777 /app/uploads

# Copy scanner from builder
COPY --from=scanner-builder /build/scanner /app/scanner

# Copy package files and install dependencies
COPY package*.json ./
RUN npm install && npm install selfsigned

# Copy all application files
COPY . .

# Set execute permissions for start.sh and scanner
RUN chmod +x start.sh scanner

# Generate SSL certificates
RUN node generate-cert.js

# Expose both HTTP and HTTPS ports
EXPOSE 3000 3443

# Use the startup script to run both services
CMD ["./start.sh"]
