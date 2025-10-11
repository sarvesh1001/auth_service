#!/bin/bash
# ===========================================================
# generate-certs.sh
# Generates a self-signed CA and TLS certificates for:
#   - Redis (redis.crt / redis.key)
#   - Go Server (server.pem / server.key)
# Outputs both ca.crt and ca.pem for compatibility
# ===========================================================

set -e

CERT_DIR="./scripts/certs"
mkdir -p "$CERT_DIR"

echo "🛠  Generating TLS certificates in: $CERT_DIR"

# -------------------------------------------------------------------
# 1. Generate CA key + certificate
# -------------------------------------------------------------------
openssl genrsa -out "$CERT_DIR/ca.key" 2048
openssl req -x509 -new -nodes -key "$CERT_DIR/ca.key" \
  -sha256 -days 3650 \
  -out "$CERT_DIR/ca.pem" \
  -subj "/C=IN/ST=State/L=City/O=Dev/OU=CA/CN=Local-CA"

# Duplicate for compatibility
cp "$CERT_DIR/ca.pem" "$CERT_DIR/ca.crt"

# -------------------------------------------------------------------
# 2. Create OpenSSL config for SAN (used by both Redis & Server)
# -------------------------------------------------------------------
cat > "$CERT_DIR/openssl.cnf" <<EOF
[ req ]
default_bits       = 2048
prompt             = no
default_md         = sha256
req_extensions     = req_ext
distinguished_name = dn

[ dn ]
C  = IN
ST = State
L  = City
O  = Dev
OU = Local
CN = localhost

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = localhost
DNS.2 = redis
IP.1  = 127.0.0.1
EOF

# -------------------------------------------------------------------
# 3. Generate Redis key + CSR + cert
# -------------------------------------------------------------------
openssl genrsa -out "$CERT_DIR/redis.key" 2048
openssl req -new -key "$CERT_DIR/redis.key" \
  -out "$CERT_DIR/redis.csr" -config "$CERT_DIR/openssl.cnf"

openssl x509 -req -in "$CERT_DIR/redis.csr" \
  -CA "$CERT_DIR/ca.pem" -CAkey "$CERT_DIR/ca.key" -CAcreateserial \
  -out "$CERT_DIR/redis.crt" -days 3650 -sha256 \
  -extensions req_ext -extfile "$CERT_DIR/openssl.cnf"

# -------------------------------------------------------------------
# 4. Generate Server key + CSR + cert
# -------------------------------------------------------------------
openssl genrsa -out "$CERT_DIR/server.key" 2048
openssl req -new -key "$CERT_DIR/server.key" \
  -out "$CERT_DIR/server.csr" -config "$CERT_DIR/openssl.cnf"

openssl x509 -req -in "$CERT_DIR/server.csr" \
  -CA "$CERT_DIR/ca.pem" -CAkey "$CERT_DIR/ca.key" -CAcreateserial \
  -out "$CERT_DIR/server.pem" -days 3650 -sha256 \
  -extensions req_ext -extfile "$CERT_DIR/openssl.cnf"

# -------------------------------------------------------------------
# 5. Cleanup
# -------------------------------------------------------------------
rm -f "$CERT_DIR/redis.csr" "$CERT_DIR/server.csr" "$CERT_DIR/ca.srl" "$CERT_DIR/openssl.cnf"

# -------------------------------------------------------------------
# 6. Summary
# -------------------------------------------------------------------
echo "✅ TLS certificates generated successfully!"
echo "----------------------------------------------"
echo "CA Certificate : $CERT_DIR/ca.pem  (also available as ca.crt)"
echo "Redis Key      : $CERT_DIR/redis.key"
echo "Redis Cert     : $CERT_DIR/redis.crt"
echo "Server Key     : $CERT_DIR/server.key"
echo "Server Cert    : $CERT_DIR/server.pem"
echo "----------------------------------------------"
echo "Use these files in Docker and Go TLSConfig."
