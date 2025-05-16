#!/bin/bash
# This script generates a self-signed SSL certificate and private key

# Check if OpenSSL is installed
if ! command -v openssl &> /dev/null
then
    echo "OpenSSL could not be found. Please install OpenSSL."
    exit 1
fi

# Ensure output directory exists
CERT_DIR="${PWD}/certs"
if [[ "$0" == "/root/generate.sh" ]]; then
    # When executed inside Docker container
    CERT_DIR="/root/certs"
fi

mkdir -p "$CERT_DIR"
echo "Creating certificates in $CERT_DIR"

# Generate a self-signed SSL certificate and private key
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout "$CERT_DIR/private.key" \
  -out "$CERT_DIR/certificate.crt" \
  -subj "/C=US/ST=California/L=San Francisco/O=My Company/CN=mydomain.com"

echo "Certificate and private key generated successfully."