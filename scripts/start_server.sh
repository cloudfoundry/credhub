#!/bin/bash

set -euo pipefail

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )"/.. && pwd )"

rm -rf "$DIR/build"
"$DIR/scripts/setup_dev_mtls.sh"
"$DIR/gradlew" --no-daemon assemble

exec "$DIR/gradlew" \
  --no-daemon \
  bootRun \
  -Djava.security.egd=file:/dev/urandom \
  -Djdk.tls.ephemeralDHKeySize=4096 \
  -Djdk.tls.namedGroups="secp384r1" \
  -Djavax.net.ssl.trustStore=src/test/resources/auth_server_trust_store.jks \
  -Djavax.net.ssl.trustStorePassword=changeit \
  -Djava.library.path=/Users/hs031209/tmp/luna-hsm-client-7.4/jsp/64 \
  -PlunaJar=/Users/hs031209/tmp/lunaclient-min-7.4.0/jsp/LunaProvider.jar \
  "$@"
 