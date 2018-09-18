#!/bin/bash

DIR="$(cd "$(dirname "$0")" && pwd)"

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
      endpoint: /tmp/sock
EOF

$DIR/start_server.sh -Dspring.profiles.active=dev,dev-external-provider,dev-h2
