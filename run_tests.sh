#!/bin/bash

run_all=$1

set -ex

if [ "$run_all" = "--run-all" ]; then
    printf "******* RUNNING ALL TESTS WITH H2 *******\n"
    ./gradlew --no-daemon clean test

    printf "******* RUNNING ALL TESTS WITH MYSQL *******\n"
    mysql --user=root --protocol=tcp --execute='DROP DATABASE IF EXISTS credhub_test; CREATE DATABASE credhub_test'
    ./gradlew --no-daemon clean test --info -Dspring.profiles.active=unit-test-mysql

    printf "******* RUNNING ALL TESTS WITH POSTGRES *******\n"
    psql -U pivotal -c "DROP DATABASE IF EXISTS credhub_test" -c "CREATE DATABASE credhub_test"
    ./gradlew --no-daemon clean test --info -Dspring.profiles.active=unit-test-postgres
else
    ./gradlew --no-daemon clean test
fi
