#!/bin/bash

set -eux
set -o pipefail

export TERM=xterm

APP_DIR=sec-eng-credential-manager

pushd $APP_DIR
./gradlew clean dependencyCheck --info
popd

echo "Credential Manager owasp check results" > ${OUTPUT_PATH}/owasp-check-email-subject.txt
cp $APP_DIR/build/reports/dependency-check-report.html ${OUTPUT_PATH}/owasp-check-email-body.txt
cat <<-EOF > ${OUTPUT_PATH}/owasp-check-email-headers.txt
MIME-version: 1.0
Content-Type: text/html; charset="UTF-8"
EOF
