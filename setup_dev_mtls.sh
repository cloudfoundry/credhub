#!/bin/bash

set -eu

DIRNAME=$(dirname "$0")

PASSWORD=changeit

DNAME='CN=localhost,C=CC'
DNAME_CA="CN=credhub_test"
DNAME_CLIENT='CN=${CLIENT_NAME}'

CA_NAME=ca
CLIENT_NAME=client_cert

KEY_STORE=key_store.jks
TRUST_STORE=trust_store.jks
# Used to store private keys of trusted CAs so we can sign client certificates.
TMP_KEY_STORE=tmp_key_store.jks

clean() {
    echo "Removing any existing key stores and certs..."
    rm -f *.jks *.crt *.csr *.p12
}

setup_key_store() {
    echo "Generating a key store for TLS..."
	keytool -genkey -alias cert \
	    -keyalg RSA -keysize 4096 -sigalg SHA512withRSA -keypass ${PASSWORD} \
	    -validity 30 -dname ${DNAME} \
	    -keystore ${KEY_STORE} -storepass ${PASSWORD}
}

setup_tmp_key_store() {
    echo "Generating a temporary key store to hold the trusted mTLS CA private keys..."
	keytool -genkey -alias ${CA_NAME} -ext BC=ca:true \
	    -keyalg RSA -keysize 4096 -sigalg SHA512withRSA -keypass ${PASSWORD} \
	    -validity 3650 -dname ${DNAME_CA} \
	    -keystore ${TMP_KEY_STORE} -storepass ${PASSWORD}
}

setup_trust_store() {
    echo "Creating a trust store with the trusted mTLS CA's certificate..."
    keytool -export -alias ${CA_NAME} -file ${CA_NAME}.crt -rfc \
	    -keystore ${TMP_KEY_STORE} -storepass ${PASSWORD}
	keytool -import -trustcacerts -noprompt -alias ${CA_NAME} -file ${CA_NAME}.crt \
	    -keystore ${TRUST_STORE} -storepass ${PASSWORD}
}

setup_trusted_certificate() {
    echo "Generating a client certificate for mutual TLS..."
    # Generate client certificate
    keytool -genkey -alias ${CLIENT_NAME} \
	    -keyalg RSA -keysize 4096 -sigalg SHA512withRSA -keypass ${PASSWORD} \
	    -validity 3650 -dname ${DNAME_CLIENT} \
	    -keystore ${TMP_KEY_STORE} -storepass ${PASSWORD}
	# Generate a host certificate signing request
	keytool -certreq -alias ${CLIENT_NAME} -ext BC=ca:true \
	    -keyalg RSA -keysize 4096 -sigalg SHA512withRSA \
	    -validity 3650 -file "${CLIENT_NAME}.csr" \
	    -keystore ${TMP_KEY_STORE} -storepass ${PASSWORD}
	# Generate signed certificate with the certificate authority
	keytool -gencert -alias ca \
	    -validity 3650 -sigalg SHA512withRSA \
	    -infile "${CLIENT_NAME}.csr" -outfile "${CLIENT_NAME}.crt" -rfc \
		-keystore ${TMP_KEY_STORE} -storepass ${PASSWORD}
    # Import now-signed cer
	keytool -import -trustcacerts -alias ${CLIENT_NAME} \
	    -file ${CLIENT_NAME}.crt \
	    -keystore ${TMP_KEY_STORE} -storepass ${PASSWORD}
	# Export private certificate for importing into a browser
	keytool -importkeystore -srcalias ${CLIENT_NAME} \
	    -srckeystore ${TMP_KEY_STORE} -srcstorepass ${PASSWORD} \
	    -destkeystore "${CLIENT_NAME}.p12" -deststorepass ${PASSWORD} \
	    -deststoretype PKCS12
}

pushd ${DIRNAME}/src/test/resources >/dev/null
    if [[ -f ${KEY_STORE} && -f ${TMP_KEY_STORE} ]]; then
        echo "Key store and trust store are already set up!"
    else
        clean
        setup_key_store
        setup_tmp_key_store
        setup_trust_store
        setup_trusted_certificate

        echo "Finished setting up key stores for TLS and mTLS!"
        echo "There is a client certificate for mTLS requests at ${PWD}/${CLIENT_NAME}.p12"
        echo e.g., curl -H \"Content-Type: application/json\" \
            -X POST -d "'{\"name\":\"cred\",\"type\":\"password\"}'" \
            https://localhost:9000/api/v1/data -k \
            --cert ${PWD}/${CLIENT_NAME}.p12:changeit
    fi
popd >/dev/null
