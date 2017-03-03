#!/bin/bash

./setup_dev_mtls.sh
./gradlew --no-daemon bootRun $@
