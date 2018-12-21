#!/usr/bin/env bash

function set_bash_error_handling() {
    set -euo pipefail
}

function go_to_project_root_directory() {
    local -r script_dir=$( dirname "${BASH_SOURCE[0]}")

    cd "$script_dir/.."
}

function clean_test_databases_postgres() {
    echo "🛁 Cleaning postgres databases"
    echo ""

    local -r credhub_test_databases=$(psql -U pivotal -c "SELECT datname FROM pg_database WHERE datistemplate = false AND datname LIKE 'credhub_test%';" -t)

    for credhub_test_database in $credhub_test_databases; do
        echo "Removing test database: $credhub_test_database"
        psql -U pivotal -c "DROP DATABASE IF EXISTS $credhub_test_database;"
        echo ""
    done

    echo "🏗️  Creating postgres test database: credhub_test"
    psql -U pivotal -c "CREATE DATABASE credhub_test;"
    echo ""
}

function run_tests_postgres() {
    local -r test_mode=${1:-}

    local gradle_test_command="test"
    if [ "$test_mode" = "parallel" ]; then
      echo "✨ Parallel test mode enabled"
      echo ""
      gradle_test_command="testParallel"
    fi

    echo "🚀 Running postgres tests"
    echo ""

    ./gradlew clean $gradle_test_command -Dspring.profiles.active=unit-test-postgres
}

function main() {
    set_bash_error_handling
    go_to_project_root_directory

    local -r test_mode=${1:-}

    clean_test_databases_postgres
    run_tests_postgres "$test_mode"
}

main "$@"
