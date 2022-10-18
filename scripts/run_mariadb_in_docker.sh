#!/usr/bin/env bash
set -e -o pipefail
container_name="credhub-mysql-dev"
db_name="credhub_test"

main() {
  trap "cleanup" EXIT

  setup &
  setup_pid=$!

  docker run \
    --name "${container_name}" \
    --rm \
    -p 3306:3306 \
    -e MARIADB_ALLOW_EMPTY_ROOT_PASSWORD=true \
    docker.io/library/mariadb
}

cleanup() {
  echo "Stopping MariaDB..."
  docker kill "${container_name}"
  kill "$setup_pid" 2>/dev/null
}

setup() {
  sleep 1
  try_connect
  echo -n "Configuring dev-database... "
  docker exec "${container_name}" bash -c "echo create database ${db_name}\; | mysql"
  echo "done"
}

try_connect() {
  started=1
  while [[ "$started" != "0" ]]
  do
    sleep 1
    echo "Attempting to connect to MariaDB..."
    set +e
    docker exec "${container_name}" bash -c "echo select 1\; | mysql" &>/dev/null
    started=$?
    set -e
  done
}

main
