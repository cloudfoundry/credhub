#!/bin/bash

curl -v --silent "http://bosh.io/releases/github.com/pivotal-cf/credhub-release?all=1" | grep --line-buffered "Upload latest version, currently" | grep -o "[0-9]\.[0-9]\.[0-9]" > version
export VERSION=$(cat version)

./setup_dev_mtls.sh
./gradlew --no-daemon bootRun $@
