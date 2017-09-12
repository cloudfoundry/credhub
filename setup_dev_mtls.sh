#!/bin/bash

set -eu

DIRNAME=$(dirname "$0")

KEYSTORE_PASSWORD=changeit

KEY_STORE=key_store.jks
MTLS_TRUST_STORE=trust_store.jks
AUTH_SERVER_TRUST_STORE=auth_server_trust_store.jks

clean() {
    echo "Removing any existing key stores and certs..."
    rm -f "${DIRNAME}"/*.jks "${DIRNAME}"/*.csr "${DIRNAME}"/*.srl "${DIRNAME}"/*.pem
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
        -deststorepass "${KEYSTORE_PASSWORD}" -destkeypass "${KEYSTORE_PASSWORD}" \
        -destkeystore "${KEY_STORE}" -alias cert

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

add_client_ca_to_trust_store() {
    echo "Adding root CA to servers trust store for mTLS..."
    keytool -import -trustcacerts -noprompt -alias client_ca -file client_ca_cert.pem \
	    -keystore ${MTLS_TRUST_STORE} -storepass ${KEYSTORE_PASSWORD}
}

setup_auth_server_trust_store() {
    echo "Adding dev UAA CA to auth server trust store"
    keytool -import \
        -trustcacerts \
        -noprompt \
        -alias auth_server_ca \
        -file <(cat <<EOF
-----BEGIN CERTIFICATE-----
MIIExTCCA62gAwIBAgIUKZo5aP6kuThYt94XC+U93cD/XSkwDQYJKoZIhvcNAQEL
BQAwgZQxHTAbBgNVBAoMFFBpdm90YWwgQ3JlZGh1YiBUZWFtMQswCQYDVQQIDAJD
QTELMAkGA1UEBhMCVVMxJzAlBgNVBAMMHlBpdm90YWwgQ3JlZGh1YiBEZXZlbG9w
bWVudCBDQTEYMBYGA1UECwwPQ3JlZGh1YiBSb290IENBMRYwFAYDVQQHDA1TYW4g
RnJhbmNpc2NvMB4XDTE3MDkxMTE0Mjg0MloXDTI3MDkwOTE0Mjg0MlowgZQxHTAb
BgNVBAoMFFBpdm90YWwgQ3JlZGh1YiBUZWFtMQswCQYDVQQIDAJDQTELMAkGA1UE
BhMCVVMxJzAlBgNVBAMMHlBpdm90YWwgQ3JlZGh1YiBEZXZlbG9wbWVudCBDQTEY
MBYGA1UECwwPQ3JlZGh1YiBSb290IENBMRYwFAYDVQQHDA1TYW4gRnJhbmNpc2Nv
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7KvHekCUfHnwQAIZUgOw
WghlHTz/CqrR5egwL1SikoHFIchLekwGoVcGpbv3D8Qd39sphi3glalc5I8VvaTE
yNp7Kz6tdnywrz0bzCn221g+MRoxNn9uY8qrNZ8jDf3Oe9FJ0ozX+73czM9G7SK6
XqaKwsyIz5d3sPtG8Qy9fyv32LE3rcJbmsOojm20jD0m9QEs2OBW98byVQjHQaWq
uZ8mWIL9oUCbgIlSdvG+9+bA2Rd6h5JDEkZA1nDFl3eg/P1GBZJxomaIoEu5MsvH
2srkmeW2hiTwtGU0ANYc+o/aXlB4GoHnJaSmHPMj187ptzU8kEtAf4K2+5yCSq6G
aQIDAQABo4IBCzCCAQcwHQYDVR0OBBYEFCC1KZxqfD/zOSHaBPxVF2SFPp1IMIHU
BgNVHSMEgcwwgcmAFCC1KZxqfD/zOSHaBPxVF2SFPp1IoYGapIGXMIGUMR0wGwYD
VQQKDBRQaXZvdGFsIENyZWRodWIgVGVhbTELMAkGA1UECAwCQ0ExCzAJBgNVBAYT
AlVTMScwJQYDVQQDDB5QaXZvdGFsIENyZWRodWIgRGV2ZWxvcG1lbnQgQ0ExGDAW
BgNVBAsMD0NyZWRodWIgUm9vdCBDQTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjb4IU
KZo5aP6kuThYt94XC+U93cD/XSkwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0B
AQsFAAOCAQEAG0doArMYOahlE3yhPhuh2KnnwTI0EESaeeHV6Dso67TouIy/oM7t
SgOfH1vdNNVwFwnY3X/ECGV0daTBbEBIWRGsyDkDRYD3LhfEQzOsHdWCdH7aKivL
Z0yYENWo0Z9qROrY9DTr7gcxPORBl1/x0O7OKIKAhtd7RwNta/LobCpnux4K0Opg
sBpFELYHtZ3DKBBQ+zsaurebIhb6I1wCGr0MxbDnU3pyWFawwraOiBW6OOPW9TgR
y5sfuaCxixB7l3bVMKlUCC6ogKRyXsegf3EFnPYC0f9Ha+AdduXOeQn9S/86Bh6v
Oo1c49U38x1R8EcN8FWzsi2nLP+hTFiLUg==
-----END CERTIFICATE-----
EOF
        ) \
        -keystore ${AUTH_SERVER_TRUST_STORE} \
        -storepass ${KEYSTORE_PASSWORD}
}

main() {
    pushd "${DIRNAME}/src/test/resources" >/dev/null
        clean
        generate_server_ca
        generate_client_ca
        add_client_ca_to_trust_store
        setup_tls_key_store
        setup_auth_server_trust_store

        echo "Finished setting up key stores for TLS and mTLS!"

        echo "Run run_tests.sh in credhub-acceptance-tests to generate client certs"
        echo e.g., curl -H \"Content-Type: application/json\" \
            -X POST -d "'{\"name\":\"cred\",\"type\":\"password\"}'" \
            https://localhost:9000/api/v1/data --cacert "${PWD}/server_ca_cert.pem" \
            --cert "${GOPATH}/src/github.com/cloudfoundry-incubator/credhub-acceptance-tests/certs/client.pem" \
            --key "${GOPATH}"/src/github.com/cloudfoundry-incubator/credhub-acceptance-tests/certs/client_key.pem

    popd >/dev/null
}

main
