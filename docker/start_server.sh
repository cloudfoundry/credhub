#!/bin/bash
set -euo pipefail

application_configs="$(find /etc/config -mindepth 1 -maxdepth 1 2>/dev/null | paste -sd ',' -)"
declare -r application_configs

"java" \
  "-Djava.security.egd=file:/dev/urandom" \
  "-Djdk.tls.ephemeralDHKeySize=4096" \
  "-Dspring.config.additional-location=${application_configs}" \
  "-Djdk.tls.namedGroups=\"secp384r1\"" \
  "-Djavax.net.ssl.trustStore=/app/stores/trust_store.jks" \
  "-Djavax.net.ssl.trustStorePassword=${TRUST_STORE_PASSWORD}" \
  "-ea" \
  "-jar" \
  "credhub.jar" \
  "--management.server.port=9001"
