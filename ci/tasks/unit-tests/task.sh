#!/bin/bash

set -eux
set -o pipefail

export TERM=xterm

service mysql start
mysql -u root -e "create database credhub_test"

service postgresql start
su - postgres -c "createuser -l -d -c 1000 root"
createdb credhub_test
psql -d credhub_test -c "ALTER USER root WITH PASSWORD 'root';"

pushd sec-eng-credential-manager
gradle -Dspring.profiles.active=${DATABASE_PROFILE} clean test
popd
