#!/bin/bash

set -euo pipefail

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )"/.. && pwd )"


if [[ $# -ne 1 ]]; then
  echo "Usage: $0 </path/to/kms/ca/cert> <optional gradle args>"
  exit 1
fi

ca_path="$1"
shift

rm -rf "$DIR/build"
"$DIR/scripts/setup_dev_mtls.sh"
"$DIR/scripts/setup_dev_grpc_certs.sh"

indented_ca=$(sed 's/^/        /' "$ca_path")
cat >"$DIR/applications/credhub-api/src/main/resources/application-kms-plugin-generated.yml" <<-EOF
encryption:
  key_creation_enabled: true
  providers:
  - provider_name: sample
    provider_type: kms-plugin
    keys:
    - active: true
      encryption_key_name: some-key-name-1
    configuration:
      endpoint: "/tmp/socket.sock"
      host: "localhost"
      ca: |
$indented_ca
EOF

exec "$DIR/gradlew" \
  --no-daemon \
  bootRun \
  -Djava.security.egd=file:/dev/urandom \
  -Djdk.tls.ephemeralDHKeySize=4096 \
  -Djdk.tls.namedGroups="secp384r1" \
  -Djavax.net.ssl.trustStore=src/test/resources/auth_server_trust_store.jks \
  -Djavax.net.ssl.trustStorePassword=changeit \
  -Dspring.profiles.active=dev,dev-h2,kms-plugin-generated \
  "$@"
