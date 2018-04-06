#!/bin/bash
set -ex

echo '******* RUNNING ALL TESTS WITH H2 *******'
./gradlew --no-daemon clean test

echo '******* RUNNING ALL TESTS WITH MYSQL *******'
mysql --user=root --protocol=tcp --execute='DROP DATABASE credhub_test; CREATE DATABASE credhub_test'
./gradlew --no-daemon clean test --info -Dspring.profiles.active=unit-test-mysql

echo '******* RUNNING ALL TESTS WITH POSTGRES *******'
psql -U pivotal -c "DROP DATABASE credhub_test" -c "CREATE DATABASE credhub_test"
./gradlew --no-daemon clean test --info -Dspring.profiles.active=unit-test-postgres
