#!/bin/bash

export VERSION=100.0.1

./setup_dev_mtls.sh
./gradlew --no-daemon assemble
./gradlew --no-daemon bootRun -Djava.security.egd=file:/dev/urandom -Djdk.tls.ephemeralDHKeySize=3072 -Djdk.tls.namedGroups="secp384r1" -Djavax.net.ssl.trustStore=src/test/resources/auth_server_trust_store.jks -Djavax.net.ssl.trustStorePassword=changeit $@
