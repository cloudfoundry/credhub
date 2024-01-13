#!/bin/bash

set -euo pipefail

generate_server_ca() {
    echo "Generating root CA for the server certificates into server_ca_cert.pem and server_ca_private.pem"
    openssl req \
      -x509 \
      -newkey rsa:2048 \
      -days 365 \
      -sha256 \
      -nodes \
      -subj "/CN=credhub_server_ca" \
      -keyout server_ca_private.pem \
      -out server_ca_cert.pem

    mkdir -p /etc/server_certs
    cp server_ca_cert.pem /etc/server_certs/server_ca_cert.pem
}

setup_tls_key_store() {
    if [[ -f "${SERVER_CA_CERT_PATH}" && -f "${SERVER_CA_PRIVATE_KEY_PATH}" ]]
    then
      echo "Using provided server CA"
      cp "${SERVER_CA_CERT_PATH}" server_ca_cert.pem
      cp "${SERVER_CA_PRIVATE_KEY_PATH}" server_ca_private.pem
    else
      generate_server_ca
    fi

    cat > server.cnf <<EOF
[v3_ca]
subjectKeyIdentifier=hash
subjectAltName="${SUBJECT_ALTERNATIVE_NAMES}"
EOF

    echo "Generating a key store for the certificate the server presents during TLS"
    # generate keypair for the server cert
    openssl genrsa -out server_key.pem 2048

    echo "Create CSR for the server cert"
    openssl req -new -sha256 -key server_key.pem -subj "/CN=localhost" -out server.csr

    echo "Generate server certificate signed by our CA"
    openssl x509 -req -in server.csr -sha384 -CA server_ca_cert.pem -CAkey server_ca_private.pem \
        -CAcreateserial -out server.pem -extensions v3_ca -extfile server.cnf

    echo "Create a .p12 file that contains both server cert and private key"
    openssl pkcs12 -export -in server.pem -inkey server_key.pem \
        -out server.p12 -name cert -password pass:changeit

    echo "Import signed certificate into the keystore"
	  keytool -importkeystore \
        -srckeystore server.p12 -srcstoretype PKCS12 -srcstorepass changeit \
        -deststorepass "${KEY_STORE_PASSWORD}" -destkeypass "${KEY_STORE_PASSWORD}" \
        -destkeystore "/app/stores/key_store.jks" -alias cert

    rm server.p12 server.csr
}

setup_auth_server_trust_store() {
  echo "Adding dev UAA CA to auth server trust store"
  keytool -import \
    -trustcacerts \
    -noprompt \
    -alias "uaa_ca" \
    -file "${UAA_CA_PATH}" \
    -keystore /app/stores/trust_store.jks \
    -storepass "${TRUST_STORE_PASSWORD}"
}

clean (){
    rm -f -- *.pem *.jks *.p12 *.srl *.cnf *csr
    find . -type f -name '*.srl' -delete
}

main() {
  pushd /app > /dev/null
    rm -rf stores
    mkdir -p stores
    setup_tls_key_store
    setup_auth_server_trust_store
  popd > /dev/null
}

main
