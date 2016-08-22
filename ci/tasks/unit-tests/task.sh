#!/bin/bash

set -eux
set -o pipefail

export TERM=xterm

pushd sec-eng-credential-manager
gradle clean test --info
popd
