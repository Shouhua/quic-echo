#! /usr/bin/env bash

# Generate self signed ca and server cert for localhost test

set -eou pipefail

CA="ca.pem"
CA_KEY="ca_key.pem"
SERVER_CERT="server_cert.pem"
SERVER_KEY="server_key.pem"
HOST="localhost"
IP="127.0.0.1"

# NOTICE quictls
export LD_LIBRARY_PATH=/usr/local/lib64
openssl version

# clean
rm -f $CA $CA_KEY $SERVER_CERT $SERVER_KEY

# 1. Generate self-signed certificate and private key
openssl req -x509 \
    -newkey rsa:4096 \
    -days 365 \
    -keyout "${CA_KEY}" \
    -out "${CA}" \
    -subj "/C=CN/ST=Hubei/L=Wuhan/O=QUIC/OU=QUICUNIT/CN=localhost/emailAddress=ca@example.com" \
    -noenc > /dev/null 2>&1

echo "CA's self-signed certificate DONE"
# openssl x509 -in "${CA}" -noout -text

# 2. Generate server cert and private key
openssl req -x509\
    -newkey rsa:4096 \
    -keyout "${SERVER_KEY}" \
    -out "${SERVER_CERT}" \
    -subj "/C=CN/ST=Hubei/L=Wuhan/O=QUIC/OU=QUICUNIT/CN=localhost/emailAddress=server@example.com" \
    -addext "subjectAltName=DNS:${HOST},IP:${IP}" \
    -CA "${CA}" \
    -CAkey "${CA_KEY}" \
    -copy_extensions copyall \
    -days 365 \
    -noenc > /dev/null 2>&1

echo "Server's certificate DONE"
# openssl x509 -in "${SERVER_CERT}" -noout -text

# 6. Verify server certificate
openssl verify \
    -verbose \
    -show_chain \
    -trusted ${CA} \
    "${SERVER_CERT}"
