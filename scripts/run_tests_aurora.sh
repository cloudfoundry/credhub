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
        # Use environment variables for remote connection, fallback to local defaults
        # AURORA_DB_HOST: hostname of the Aurora/MySQL server (omit for localhost via TCP)
        # AURORA_DB_PORT: port number (omit for default 3306)
        # AURORA_DB_USERNAME: database username (defaults to 'root')
        # AURORA_DB_PASSWORD: database password (omit if empty)
        mysql --protocol=tcp \
            ${AURORA_DB_HOST:+--host=$AURORA_DB_HOST} \
            ${AURORA_DB_PORT:+--port=$AURORA_DB_PORT} \
            --user=${AURORA_DB_USERNAME:-root} \
            ${AURORA_DB_PASSWORD:+--password=$AURORA_DB_PASSWORD} \
            --execute "DROP DATABASE IF EXISTS $credhub_test_database;"
        echo ""
    done

    echo "🏗️  Creating mysql test database: credhub_test"
    mysql --user=root --protocol=tcp --execute "CREATE DATABASE credhub_test;"
    echo ""
}

function run_tests_aurora() {
    local gradle_test_command="test"
    echo "✨ Parallel test mode enabled"
    echo "🚀 Running aurora tests"
    echo ""

    mysql --protocol=tcp --user=root --protocol=tcp --execute "SET GLOBAL max_connections = 1000;"
    ./gradlew clean $gradle_test_command -Dspring.profiles.active=unit-test-aurora
}

function main() {
    set_bash_error_handling
    go_to_project_root_directory

    clean_test_databases_mysql
    run_tests_aurora
}

main
