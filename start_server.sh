#!/bin/bash

export VERSION=100.0.1

./setup_dev_mtls.sh
./gradlew --no-daemon bootRun $@
