#!/usr/bin/env bash

function set_bash_error_handling() {
    set -euo pipefail
}

function go_to_project_root_directory() {
    local -r script_dir=$( dirname "${BASH_SOURCE[0]}")

    cd "$script_dir/.."
}

function clean_test_databases_mysql() {
    echo "🛁 Cleaning mysql databases"
    echo ""

    local -r credhub_test_databases=$(mysql --user=root --protocol=tcp --execute="SHOW DATABASES LIKE 'credhub_test%';" -sN)

    for credhub_test_database in $credhub_test_databases; do
        echo "Removing test database: $credhub_test_database"
        mysql --protocol=tcp --user=root --protocol=tcp --execute "DROP DATABASE IF EXISTS $credhub_test_database;"
        echo ""
    done

    echo "🏗️  Creating mysql test database: credhub_test"
    mysql --user=root --protocol=tcp --execute "CREATE DATABASE credhub_test;"
    echo ""
}

function run_tests_mysql() {
    local gradle_test_command=":backends:credhub:test"
    echo "✨ Parallel test mode enabled"
    echo "🚀 Running mysql tests"
    echo ""

    mysql --protocol=tcp --user=root --protocol=tcp --execute "SET GLOBAL max_connections = 1000;"
    ./gradlew clean $gradle_test_command -Dspring.profiles.active=unit-test-mysql \
    --tests "org.cloudfoundry.credhub.endToEnd.v2.permissions.UpdatePermissionsV2EndToEndTest" \
    --tests "org.cloudfoundry.credhub.endToEnd.v2.permissions.AddPermissionsV2EndToEndTest" \
    --tests "org.cloudfoundry.credhub.endToEnd.v2.permissions.DeletePermissionsV2EndToEndTest" \
    --tests "org.cloudfoundry.credhub.endToEnd.v2.permissions.GetPermissionsV2EndToEndTest"
}

function main() {
    set_bash_error_handling
    go_to_project_root_directory

    clean_test_databases_mysql
    run_tests_mysql
}

main
