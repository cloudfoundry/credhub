#!/bin/bash

set -eux
set -o pipefail

export TERM=xterm

pushd credhub-src
    gradle clean dependencyCheck
popd

echo "Credential Manager owasp check results" > ${OUTPUT_PATH}/owasp-check-email-subject.txt
cp credhub-src/build/reports/dependency-check-report.html ${OUTPUT_PATH}/owasp-check-email-body.txt
cat <<-EOF > ${OUTPUT_PATH}/owasp-check-email-headers.txt
MIME-version: 1.0
Content-Type: text/html; charset="UTF-8"
EOF
