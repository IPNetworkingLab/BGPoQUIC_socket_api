#!/usr/bin/env bash

set -e

if [ "$#" != "5" ]; then
  echo "This script takes 5 args."
  echo "$0 <dest_dir> <certificate_name> <dns_name> <ip> <router_config>"
  exit 1
fi

DEST_DIR=$1
NAME=$2
COMMON_NAME=$3
ALT_NAME_IP=$4
CONFIG_RTR=$5

CA_KEY="$DEST_DIR"/ca.key
CA_CRT="$DEST_DIR"/ca.cert.pem
CA_CFG_FILE="$(mktemp)"

RTR_KEY="$DEST_DIR"/"$NAME".key
RTR_CSR="$DEST_DIR"/"$NAME".csr
RTR_CRT="$DEST_DIR"/"$NAME".cert.pem
RTR_CFG="$(mktemp)"

# CONFIG for V3_EXT
V3_EXT="$(mktemp)"

cat <<EOF > "$V3_EXT"
nsCertType = server, client
subjectKeyIdentifier = hash
#authorityKeyIdentifier = keyid,issuer:always
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names
1.2.3.4 = ASN1:UTF8String:"$(base64 -w0 < "$CONFIG_RTR")"
[alt_names]
DNS.1 = $COMMON_NAME
DNS.2 = www.$COMMON_NAME
IP.1 = $ALT_NAME_IP
EOF

# Config for root CA
cat <<EOF > "$CA_CFG_FILE"
[ req ]
# Extension to add when the -x509 option is used.
x509_extensions     = v3_ca
distinguished_name  = req_distinguished_name
prompt = no

[ req_distinguished_name ]
countryName         = BE
stateOrProvinceName = "Brabant Wallon"
localityName        = "Louvain-la-Neuve"
organizationName    = "BGOoQUIC"
commonName          = "Router Root CA"
emailAddress        = thomas@eyes.com

[ v3_ca ]
# Extensions for a typical CA (man x509v3_config).
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
# extendedKeyUsage = clientAuth, emailProtection
EOF


# Config for Router Certificate
cat <<EOF > "$RTR_CFG"
[req]
distinguished_name = dn
prompt=no
req_extensions=req_ext

[dn]
C="BE"
ST="Brabant wallon"
O="Université catholique de Louvain"
CN="$COMMON_NAME"

[req_ext]
$(cat "$V3_EXT")
EOF

if [ ! -f "$CA_KEY" ]; then
  echo "No Root CA, generating one..."
  #1. Generate CA pkey
  openssl genpkey -algorithm ED25519 > "$CA_KEY"
  #2. Generate Root CA
  openssl req -new -x509 -days 365 -key "$CA_KEY" -out "$CA_CRT" -config "$CA_CFG_FILE"
fi

#3. Generate rtr server key
openssl genpkey -algorithm ED25519 > "$RTR_KEY"

#4. Generate signing request for rtr certificate
openssl req -new -key "$RTR_KEY" -out "$RTR_CSR" -config "$RTR_CFG"

#5. Sign rtr certificate with CA
openssl x509 -req -days 365 -in "$RTR_CSR" -CA "$CA_CRT" -CAkey "$CA_KEY" \
             -CAcreateserial -out "$RTR_CRT" -extfile "$V3_EXT"

#### Optionally verify crt
#openssl x509 -noout -text -in "$RTR_CRT"

# Clean our mess
rm "$CA_CFG_FILE" "$RTR_CFG" "$RTR_CSR" "$V3_EXT"