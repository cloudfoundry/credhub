#!/usr/bin/env bash
set -eu -o pipefail
container_name="credhub-postgres-dev"
db_names="credhub_test pivotal"
username="pivotal"

main() {
  trap "cleanup" EXIT

  setup &
  setup_pid=$!

  docker run \
    --name "${container_name}" \
    --rm \
    -p 5432:5432 \
    -e POSTGRES_HOST_AUTH_METHOD=trust \
    docker.io/library/postgres
}

cleanup() {
  echo "Stopping Postgres..."
  docker kill "${container_name}"
  kill "$setup_pid" 2>/dev/null
}

setup() {
  sleep 1
  try_connect
  echo -n "Configuring dev-user and database... "
  docker exec "${container_name}" createuser -U postgres --createdb "${username}"
  for db_name in ${db_names}
  do
    docker exec "${container_name}" createdb -U "${username}" "${db_name}"
  done

  echo "done"
}

try_connect() {
  started=1
  while [[ "$started" != "0" ]]
  do
    sleep 1
    echo "Attempting to connect to Postgres..."
    set +e
    docker exec "${container_name}" psql -U postgres -v "ON_ERROR_STOP=1" -c "SELECT 1" >/dev/null
    started=$?
    set -e
  done
}

main
