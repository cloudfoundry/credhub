#!/usr/bin/env bash

set -euo pipefail

namespace="/test-rotation"

echo "Deleting existing certs"
for cred in $(credhub find | grep "$namespace" | awk '{ print $3 }'); do
  credhub delete -n "$cred" >/dev/null 2>&1 &
done
wait

echo "Generating root $namespace/cert-1"
credhub generate -t certificate -n "$namespace/cert-1" --common-name "$namespace/cert-1" --is-ca --self-sign >/dev/null 2>&1

echo "Generating intermediate $namespace/cert-2 signed by $namespace/cert-1"
credhub generate -t certificate -n "$namespace/cert-2" --common-name "$namespace/cert-2" --is-ca --ca "$namespace/cert-1" >/dev/null 2>&1
echo "Generating intermediate $namespace/cert-3 signed by $namespace/cert-1"
credhub generate -t certificate -n "$namespace/cert-3" --common-name "$namespace/cert-3" --is-ca --ca "$namespace/cert-1" >/dev/null 2>&1

echo "Generating intermediate $namespace/cert-4 signed by $namespace/cert-3"
credhub generate -t certificate -n "$namespace/cert-4" --common-name "$namespace/cert-4" --is-ca --ca "$namespace/cert-3" >/dev/null 2>&1
echo "Generating intermediate $namespace/cert-5 signed by $namespace/cert-3"
credhub generate -t certificate -n "$namespace/cert-5" --common-name "$namespace/cert-5" --is-ca --ca "$namespace/cert-3" >/dev/null 2>&1
echo "Generating intermediate $namespace/cert-6 signed by $namespace/cert-3"
credhub generate -t certificate -n "$namespace/cert-6" --common-name "$namespace/cert-6" --is-ca --ca "$namespace/cert-3" >/dev/null 2>&1

echo "Generating leaf $namespace/cert-7 signed by $namespace/cert-6"
credhub generate -t certificate -n "$namespace/cert-7" --common-name "$namespace/cert-7" --ca "$namespace/cert-6" >/dev/null 2>&1
echo "Generating leaf $namespace/cert-8 signed by $namespace/cert-6"
credhub generate -t certificate -n "$namespace/cert-8" --common-name "$namespace/cert-8" --ca "$namespace/cert-6" >/dev/null 2>&1
echo "Generating leaf $namespace/cert-9 signed by $namespace/cert-6"
credhub generate -t certificate -n "$namespace/cert-9" --common-name "$namespace/cert-9" --ca "$namespace/cert-6" >/dev/null 2>&1

echo "Generating three additional versions of $namespace/cert-6"
credhub regenerate -n "$namespace/cert-6" >/dev/null 2>&1
credhub regenerate -n "$namespace/cert-6" >/dev/null 2>&1
credhub regenerate -n "$namespace/cert-6" >/dev/null 2>&1

echo "Generating a transitional version of $namespace/cert-6"
cert6Id="$(credhub curl -p "/api/v1/certificates?name=$namespace/cert-6" | jq -r .certificates[0].id)"
credhub curl -X POST -p "/api/v1/certificates/$cert6Id/regenerate" -d '{"set_as_transitional": true}' >/dev/null 2>&1

echo -e "\n\n\n\n\n"
echo -e "You can run the following command to verify the new behavior:"
echo -e "'credhub curl -p "/api/v1/certificates?name=$namespace/cert-6"'\n"
echo -e "You should notice that the certificate shows five versions. Each version should have an 'expiry_date', and one should be transitional."
echo -e "You should also notice that the certificate is signed by '$namespace/cert-3' and signs '$namespace/cert-7', '$namespace/cert-8', and '$namespace/cert-9'.\n\n"

echo -e "You can also run the following command to verify that the behavior is the same when getting all certificates:"
echo -e "'credhub curl -p \"/api/v1/certificates\"'"
