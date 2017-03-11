#!/bin/bash

set -eu

DIRNAME=$(dirname "$0")

KEYSTORE_PASSWORD=changeit

SERVER_DNAME='localhost'
CLIENT_DNAME='credhub_client'
CA_DNAME="credhub_client_ca"

CA_NAME=ca
CLIENT_NAME=client

KEY_STORE=key_store.jks
TRUST_STORE=trust_store.jks

clean() {
    echo "Removing any existing key stores and certs..."
    rm -f *.jks *.csr *.srl *pem
}

setup_tls_key_store() {
    echo "Generating a key store for the certificate the server presents during TLS"
    # generate keypair for the server cert
	openssl genrsa -out server_key.pem 2048

	echo "Create CSR for the server cert"
    openssl req -new -sha256 -key server_key.pem -subj "/CN=${SERVER_DNAME}" -out server.csr

    echo "Generate server certificate signed by our CA"
    openssl x509 -req -in server.csr -CA ${CA_NAME}.pem -CAkey ${CA_NAME}_key.pem \
        -CAcreateserial -out server.pem

    echo "Create a .p12 file that contains both server cert and private key"
    openssl pkcs12 -export -in server.pem -inkey server_key.pem \
        -out server.p12 -name cert -password pass:changeit

    echo "Import signed certificate into the keystore"
	keytool -importkeystore \
        -srckeystore server.p12 -srcstoretype PKCS12 -srcstorepass changeit \
        -deststorepass ${KEYSTORE_PASSWORD} -destkeypass ${KEYSTORE_PASSWORD} \
        -destkeystore ${KEY_STORE} -alias cert

    rm server.p12 server.csr
}

generate_ca() {
    echo "Generating root CA for both client and server certificates into ${CA_NAME}.pem and ${CA_NAME}_key.pem"
    openssl req \
      -x509 \
      -newkey rsa:2048 \
      -days 30 \
      -sha256 \
      -nodes \
      -subj "/CN=${CA_DNAME}" \
      -keyout ${CA_NAME}_key.pem \
      -out ${CA_NAME}.pem
}

add_ca_to_truststore() {
    echo "Adding root CA to servers trust store for mTLS..."
    keytool -import -trustcacerts -noprompt -alias ${CA_NAME} -file ${CA_NAME}.pem \
	    -keystore ${TRUST_STORE} -storepass ${KEYSTORE_PASSWORD}
}

pushd ${DIRNAME}/src/test/resources >/dev/null
    if [[ -f ${KEY_STORE} && -f ${TRUST_STORE} ]]; then
        echo "Key store and trust store are already set up!"
    else
        clean
        generate_ca
        add_ca_to_truststore
        setup_tls_key_store

        echo "Finished setting up key stores for TLS and mTLS!"
        echo e.g., curl -H \"Content-Type: application/json\" \
            -X POST -d "'{\"name\":\"cred\",\"type\":\"password\"}'" \
            https://localhost:9000/api/v1/data -k \
            --cert ${PWD}/${CLIENT_NAME}.pem --key ${PWD}/${CLIENT_NAME}_key.pem
    fi
popd >/dev/null
