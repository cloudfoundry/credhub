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
MIIDyzCCArOgAwIBAgIUUH9NMMgv8OC6vdGN0ul9fTzIBpMwDQYJKoZIhvcNAQEL
BQAwgZQxHTAbBgNVBAoMFFBpdm90YWwgQ3JlZEh1YiBUZWFtMQswCQYDVQQIDAJD
QTELMAkGA1UEBhMCVVMxJzAlBgNVBAMMHlBpdm90YWwgQ3JlZEh1YiBEZXZlbG9w
bWVudCBDQTEYMBYGA1UECwwPQ3JlZEh1YiBSb290IENBMRYwFAYDVQQHDA1TYW4g
RnJhbmNpc2NvMB4XDTE2MDkwOTIzMTMyOVoXDTE3MDkwOTIzMTMyOVowgZQxHTAb
BgNVBAoMFFBpdm90YWwgQ3JlZEh1YiBUZWFtMQswCQYDVQQIDAJDQTELMAkGA1UE
BhMCVVMxJzAlBgNVBAMMHlBpdm90YWwgQ3JlZEh1YiBEZXZlbG9wbWVudCBDQTEY
MBYGA1UECwwPQ3JlZEh1YiBSb290IENBMRYwFAYDVQQHDA1TYW4gRnJhbmNpc2Nv
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAhZN/2O6Yij0zb5RSHnBk
7xObY4yHPFWA0pUuYK8hUSLlbyPz7OsSw2zmIRAza7jQ6HO5RBjFkXo3RuHSnu+Y
W5+YP7GzLo13Hpq58kyoVbYxy5aaX5vIQnkacOo/PXAI18Cb/RVuCyvrSalYGNhc
hp/us1TyHHhiM84/mcxMuQWXDOLVI78p+iSQ5VvGBBPWe6wJ7dYPNR1rbLpyVhAG
J/5XfEln+s2JMy+9uT7EOyYuMGJ7f42g9ZkaXYSZjkr9jNA2QoyL2TESaldBM7nv
lVUy94WQUQwwddVZ9Zz0nMO0jrzvJefoDZhrgKA8aZ1HfyHbzofHzzAuuvx95S5Z
ywIDAQABoxMwETAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBV
IhijrH8Q/iQOSwfkctTQ/y1jjDKXJYhmAMRfWjpgVQErJmh26/b3W8Z79HRW81J6
DOvWXP5ipuaCln3/1TpZ+fbvhq4455NkCg3Sd5Jg8UJZgk8G4Ajacwr2Co4nEw+u
37NL8y/khme5FIGfBTaaillY7dILWVApUf9kAs/66Scn1WGH6eKoYbFc0Ihjgfqm
Z66j42ElaTHee2aW9D1MtmWrN2biKt5P2BDFZjgFdfKWVE5ZbBOXu5E0vyEnOA+1
PMkj8Mn80l+rLZmjltFdP+2OKzJLsDelB/TMGskWBOwdz125ICw31QldqPffygSD
9Y0zSr/HiQn6H6wMIifS
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
