#!/bin/bash

set -eux

echo "Database Profile = $1"
DATABASE_PROFILE=$1 fly \
  -t private \
  execute \
  -c task.yml \
  -i sec-eng-credential-manager=$HOME/workspace/credhub-release/src/credhub
