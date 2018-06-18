#!/bin/bash

set -euo pipefail

export VERSION=100.0.1

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

$DIR/setup_dev_mtls.sh
$DIR/gradlew --no-daemon assemble
exec $DIR/gradlew --no-daemon bootRun -Djava.security.egd=file:/dev/urandom -Djdk.tls.ephemeralDHKeySize=4096 -Djdk.tls.namedGroups="secp384r1" -Djavax.net.ssl.trustStore=src/test/resources/auth_server_trust_store.jks -Djavax.net.ssl.trustStorePassword=changeit $@
