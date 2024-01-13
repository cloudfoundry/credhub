#!/usr/bin/env bash

set -euo pipefail

function go_to_project_root_directory() {
    local -r script_dir=$( dirname "${BASH_SOURCE[0]}")

    cd "$script_dir/.."
}

function lint_scripts() {
    shellcheck -- */*.sh
}

function lint_jvm_language_code() {
    ./gradlew ktlintFormat
    ./gradlew clean check -x test
}

function main() {
    go_to_project_root_directory

    lint_scripts
    lint_jvm_language_code
}

main "$@"
