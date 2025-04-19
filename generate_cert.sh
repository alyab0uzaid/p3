#!/bin/bash
# Script to generate self-signed certificates for P3
# This creates p3server.key and p3server.crt as required by the assignment

# Generate private key
openssl genrsa -out p3server.key 2048

# Generate self-signed certificate
openssl req -new -x509 -key p3server.key -out p3server.crt -days 365 \
    -subj "/C=US/ST=Illinois/L=Edwardsville/O=SIUE/OU=CS447/CN=localhost"

# Set permissions
chmod 600 p3server.key
chmod 644 p3server.crt

# Display certificate information
echo "Certificate generated successfully:"
echo "Certificate subject:"
openssl x509 -in p3server.crt -noout -text | grep Subject:
echo "Validity:"
openssl x509 -in p3server.crt -noout -dates

echo "Files generated:"
ls -l p3server.key p3server.crt 