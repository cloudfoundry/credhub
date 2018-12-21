#!/usr/bin/env bash

function set_bash_error_handling() {
    set -euo pipefail
}

function go_to_project_root_directory() {
    local -r script_dir=$( dirname "${BASH_SOURCE[0]}")

    cd "$script_dir/.."
}

function run_tests_h2() {

    local -r test_mode=${1:-}

    local gradle_test_command="test"
    if [ "$test_mode" = "parallel" ]; then
      echo "✨ Parallel test mode enabled"
      echo ""
      gradle_test_command="testParallel"
    fi

    echo "🚀 Running h2 tests"
    echo ""

    ./gradlew clean $gradle_test_command -Dspring.profiles.active=unit-test-h2
}

function main() {
    set_bash_error_handling
    go_to_project_root_directory

    local -r test_mode=${1:-}

    run_tests_h2 "$test_mode"
}

main "$@"
