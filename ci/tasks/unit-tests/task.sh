#!/bin/bash

set -eux
set -o pipefail

export TERM=xterm

pushd sec-eng-credential-manager
gradle -Dspring.profiles.active=${DATABASE_PROFILE} clean test
popd
