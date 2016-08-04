#!/bin/bash

set -eux
set -o pipefail

export TERM=xterm

pushd sec-eng-credential-manager
./gradlew clean test --info
popd
