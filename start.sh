#!/bin/sh

# Generate self-signed SSL certificate if it doesn't exist
if [ ! -f "certs/key.pem" ] || [ ! -f "certs/cert.pem" ]; then
    echo "Generating self-signed SSL certificate..."
    mkdir -p certs
    openssl req -x509 -newkey rsa:4096 -keyout certs/key.pem -out certs/cert.pem \
        -days 365 -nodes -subj "/CN=localhost"
    echo "SSL certificate generated."
fi

# Start the Node.js application
echo "Starting PearlGuard web application..."
node server.js
