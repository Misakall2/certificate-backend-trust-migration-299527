#!/usr/bin/env bash
# Generates the fixed certificate fixtures embedded in
# tests/unit/x509-verify-backend-fixtures.js.
#
# All certificates are generated locally with OpenSSL; nothing is
# downloaded and no real service is contacted. Only certificates
# (public data) are embedded in the test fixtures. Private keys are
# written to the output directory so the certificates can be
# regenerated or inspected, and must NOT be committed to the
# repository.
#
# Usage: tests/support/generate-x509-verify-fixtures.sh <output-dir>
set -euo pipefail

out="${1:?usage: generate-x509-verify-fixtures.sh <output-dir>}"
mkdir -p "$out"
# prevent MSYS/Git Bash from rewriting -subj arguments as paths
export MSYS2_ARG_CONV_EXCL='*'

# extension files (process substitution is not usable with native
# Windows OpenSSL builds)
printf "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n" \
  > "$out/leaf.ext"

# --- EC P-256 root CA and leaf (ecdsa-with-SHA256) ---
openssl ecparam -name prime256v1 -genkey -noout -out "$out/ec-root.key"
openssl req -x509 -new -key "$out/ec-root.key" -sha256 -days 3650 \
  -subj "/CN=Fixture EC Root" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out "$out/ec-root.crt"

openssl ecparam -name prime256v1 -genkey -noout -out "$out/ec-leaf.key"
openssl req -new -key "$out/ec-leaf.key" -sha256 \
  -subj "/CN=Fixture EC Leaf" -out "$out/ec-leaf.csr"
openssl x509 -req -in "$out/ec-leaf.csr" \
  -CA "$out/ec-root.crt" -CAkey "$out/ec-root.key" -CAcreateserial \
  -sha256 -days 3650 \
  -extfile "$out/leaf.ext" \
  -out "$out/ec-leaf.crt"

# --- EC P-256 unrelated root (not an issuer of the leaf) ---
openssl ecparam -name prime256v1 -genkey -noout -out "$out/ec-other.key"
openssl req -x509 -new -key "$out/ec-other.key" -sha256 -days 3650 \
  -subj "/CN=Fixture EC Other" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out "$out/ec-other.crt"

# --- RSA root CA and leaf signed with RSASSA-PSS (SHA-256, MGF1
# --- SHA-256, salt length 32): allowed by the node backend policy ---
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$out/pss-root.key" \
  -sha256 -days 3650 -subj "/CN=Fixture PSS Root" \
  -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 \
  -sigopt rsa_mgf1_md:sha256 \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out "$out/pss-root.crt"

openssl req -newkey rsa:2048 -nodes -keyout "$out/pss-leaf.key" \
  -sha256 -subj "/CN=Fixture PSS Leaf" -out "$out/pss-leaf.csr"
openssl x509 -req -in "$out/pss-leaf.csr" \
  -CA "$out/pss-root.crt" -CAkey "$out/pss-root.key" -CAcreateserial \
  -sha256 -days 3650 \
  -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 \
  -sigopt rsa_mgf1_md:sha256 \
  -extfile "$out/leaf.ext" \
  -out "$out/pss-leaf.crt"

# --- RSA certificate signed with RSASSA-PSS using SHA-1 parameters:
# --- cryptographically valid but rejected by the fixed parameter
# --- policy of the node backend ---
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$out/pss-sha1.key" \
  -sha1 -days 3650 -subj "/CN=Fixture PSS SHA1" \
  -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:20 \
  -sigopt rsa_mgf1_md:sha1 \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out "$out/pss-sha1.crt"

echo "Fixtures generated in $out (private keys present; do not commit)."
