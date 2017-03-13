#!/bin/bash

set -eu

DIRNAME=$(dirname "$0")

KEYSTORE_PASSWORD=changeit

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
    openssl req -new -sha256 -key server_key.pem -subj "/CN=localhost" -out server.csr

    echo "Generate server certificate signed by our CA"
    openssl x509 -req -in server.csr -CA server_ca_cert.pem -CAkey server_ca_private.pem \
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
}

generate_client_ca() {
    echo "Generating root CA for the client certificates into client_ca_cert.pem and client_ca_private.pem"
    openssl req \
      -x509 \
      -newkey rsa:2048 \
      -days 365 \
      -sha256 \
      -nodes \
      -subj "/CN=credhub_client_ca" \
      -keyout client_ca_private.pem \
      -out client_ca_cert.pem
}

add_client_ca_to_truststore() {
    echo "Adding root CA to servers trust store for mTLS..."
    keytool -import -trustcacerts -noprompt -alias client_ca -file client_ca_cert.pem \
	    -keystore ${TRUST_STORE} -storepass ${KEYSTORE_PASSWORD}
}

pushd ${DIRNAME}/src/test/resources >/dev/null
    if [[ -f ${KEY_STORE} && -f ${TRUST_STORE} ]]; then
        echo "Key store and trust store are already set up!"
    else
        clean
        generate_server_ca
        generate_client_ca
        add_client_ca_to_truststore
        setup_tls_key_store

        echo "Finished setting up key stores for TLS and mTLS!"

        echo "Run run_tests.sh in credhub-acceptance-tests to generate client certs"
        echo e.g., curl -H \"Content-Type: application/json\" \
            -X POST -d "'{\"name\":\"cred\",\"type\":\"password\"}'" \
            https://localhost:9000/api/v1/data --cacert ${PWD}/server_ca_cert.pem \
            --cert ${GOPATH}/src/github.com/cloudfoundry-incubator/credhub-acceptance-tests/certs/client.pem \
            --key ${GOPATH}/src/github.com/cloudfoundry-incubator/credhub-acceptance-tests/certs/client_key.pem
    fi
popd >/dev/null
