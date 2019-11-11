#!/bin/bash

set -euo pipefail

KEYSTORE_PASSWORD=changeit
KEY_STORE=trust_store.jks

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )"/.. && pwd )"

rm -rf "$DIR/build"
"$DIR/scripts/setup_dev_mtls.sh"
"$DIR/gradlew" --no-daemon downloadBouncyCastleFips
"$DIR/gradlew" --no-daemon assemble

pushd "$HOME/workspace/credhub-deployments/directors/dev-envs" >/dev/null
  eval "$(bbl print-env)"
popd >/dev/null

pushd "${DIR}/applications/credhub-api/src/test/resources" >/dev/null
  credhub generate -t certificate -n credhook-ca -c localhost --is-ca
  credhub get -n credhook-ca -k certificate > credhook_ca_cert.pem

  keytool -import -trustcacerts -noprompt -alias credhook-cert -file credhook_ca_cert.pem \
    -keystore ${KEY_STORE} -storepass ${KEYSTORE_PASSWORD}
popd >/dev/null

exec "$DIR/gradlew" \
  --no-daemon \
  bootRun \
  -Djava.security.egd=file:/dev/urandom \
  -Djdk.tls.ephemeralDHKeySize=4096 \
  -Djdk.tls.namedGroups="secp384r1" \
  -Djavax.net.ssl.trustStore=src/test/resources/auth_server_trust_store.jks \
  -Djavax.net.ssl.trustStorePassword=changeit "$@"
