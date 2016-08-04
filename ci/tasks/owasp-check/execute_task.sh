#!/bin/bash

set -eux

fly \
  -t private \
  execute \
  -c task.yml \
  -i sec-eng-credential-manager=$HOME/workspace/cm-release/src/credhub
