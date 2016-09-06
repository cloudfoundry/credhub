#!/bin/bash

set -eux

fly \
  -t private \
  execute \
  -c task.yml \
  -i sec-eng-credential-manager=$HOME/workspace/credhub-release/src/credhub
