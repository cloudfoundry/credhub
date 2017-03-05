#!/bin/bash

set -eu

DIRNAME=$(dirname "$0")

PASSWORD=changeit

DNAME='CN=localhost'
DNAME_CA="CN=credhub_test"

CA_NAME=ca
CLIENT_NAME=client

KEY_STORE=key_store.jks
TRUST_STORE=trust_store.jks

clean() {
    echo "Removing any existing key stores and certs..."
    rm -f *.jks *.csr *.srl *pem
}

setup_tls_key_store() {
    echo "Generating a key store for TLS..."
	keytool -genkey -alias cert \
	    -keyalg RSA -keysize 4096 -sigalg SHA512withRSA -keypass ${PASSWORD} \
	    -validity 365 -dname ${DNAME} \
	    -keystore ${KEY_STORE} -storepass ${PASSWORD}
}

generate_ca() {
    echo "Generating self signed CA..."
    openssl req \
      -x509 \
      -newkey rsa:2048 \
      -days 30 \
      -sha256 \
      -nodes \
      -subj "/CN=${DNAME_CA}" \
      -keyout ${CA_NAME}_key.pem\
      -out ${CA_NAME}.pem
}

add_ca_to_trusted_keystore() {
    echo "Adding CA to trust store for mTLS..."
    keytool -import -trustcacerts -noprompt -alias ${CA_NAME} -file ${CA_NAME}.pem \
	    -keystore ${TRUST_STORE} -storepass ${PASSWORD}
}

generate_client_cert() {
    echo "Generating client certificate signed by the trusted CA..."
    # generate keypair
    openssl genrsa -out ${CLIENT_NAME}_key.pem 2048

    # create CSR
    openssl req -new -key ${CLIENT_NAME}_key.pem -out client.csr -subj "/CN=${DNAME}"

    # create client certificate signed by the trusted CA
    openssl x509 \
        -req \
        -in client.csr \
        -CA ${CA_NAME}.pem \
        -CAkey ${CA_NAME}_key.pem \
        -CAcreateserial \
        -out ${CLIENT_NAME}.pem \
        -days 30 \
        -sha256
}

pushd ${DIRNAME}/src/test/resources >/dev/null
    if [[ -f ${KEY_STORE} && -f ${TMP_KEY_STORE} ]]; then
        echo "Key store and trust store are already set up!"
    else
        clean
        setup_tls_key_store
        generate_ca
        add_ca_to_trusted_keystore
        generate_client_cert

        echo "Finished setting up key stores for TLS and mTLS!"
        echo e.g., curl -H \"Content-Type: application/json\" \
            -X POST -d "'{\"name\":\"cred\",\"type\":\"password\"}'" \
            https://localhost:9000/api/v1/data -k \
            --cert ${PWD}/${CLIENT_NAME}.pem --key ${PWD}/${CLIENT_NAME}_key.pem
    fi
popd >/dev/null
