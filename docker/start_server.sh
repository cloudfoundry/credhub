#!/bin/bash
set -euo pipefail

declare -r application_configs="$(ls -d /etc/config/* 2>/dev/null | paste -sd ',' -)"

"java" \
  "-Djava.security.egd=file:/dev/urandom" \
  "-Djdk.tls.ephemeralDHKeySize=4096" \
  "-Dspring.config.additional-location=$application_configs" \
  "-Djdk.tls.namedGroups=\"secp384r1\"" \
  "-Djavax.net.ssl.trustStore=/app/stores/trust_store.jks" \
  "-Djavax.net.ssl.trustStorePassword=${TRUST_STORE_PASSWORD}" \
  "-ea" \
  "-jar" \
  "credhub.jar" \
  "--management.server.port=9001"
