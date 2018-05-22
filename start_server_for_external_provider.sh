#!/bin/bash

DIR="$(cd "$(dirname "$0")" && pwd)"

mtlsDir="$1"
if [[ -z "$mtlsDir" ]]; then
    echo "usage: $0 <path/to/mTLS/dir>"
    exit 1
fi

cat > $DIR/src/main/resources/application-dev-external-provider.yml <<-EOF
encryption:
  key_creation_enabled: true
  providers:
  - provider_name: ext
    provider_type: external
    keys:
    - encryption_key_name: some-key-name-1
      active: true
    configuration:
      host: localhost
      port: 50051
      server_ca: |
$(cat "$mtlsDir/ca.crt" | sed -e 's/^/        /')
      client_certificate: |
$(cat "$mtlsDir/client.crt" | sed -e 's/^/        /')
      client_key: |
$(cat "$mtlsDir/client.p8" | sed -e 's/^/        /')
EOF

$DIR/start_server.sh -Dspring.profiles.active=dev,dev-external-provider,dev-h2
