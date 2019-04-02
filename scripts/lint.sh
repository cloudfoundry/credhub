#!/usr/bin/env bash

function set_bash_error_handling() {
    set -euo pipefail
}

function go_to_project_root_directory() {
    local -r script_dir=$( dirname "${BASH_SOURCE[0]}")

    cd "$script_dir/.."
}

function download_bouncy_castle_fips() {
    ./gradlew --no-daemon downloadBouncyCastleFips
}

function lint_scripts() {
    shellcheck scripts/*.sh
}

function lint_jvm_language_code() {
    ./gradlew check -x test
}

function main() {
    set_bash_error_handling
    go_to_project_root_directory

    download_bouncy_castle_fips
    lint_scripts
    lint_jvm_language_code
}

main "$@"
