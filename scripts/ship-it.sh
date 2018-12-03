#!/usr/bin/env bash

function set_bash_error_handling() {
    set -euo pipefail
}

function go_to_project_root_directory() {
    local -r script_dir=$( dirname "${BASH_SOURCE[0]}")

    cd "$script_dir/.."
}

function check_ssh_key() {
    if ! ssh-add -l >/dev/null; then
        echo "No SSH key loaded! Please run vkl."
        exit 1
    fi
}

function run_linters() {
    ./scripts/lint.sh
}

function run_tests() {
    ./scripts/run_tests.sh
}

function push_code() {
    git push
}

function display_ascii_success_message() {
    local -r GREEN_COLOR_CODE='\033[1;32m'
    echo -e "${GREEN_COLOR_CODE}\\n$(cat scripts/success_ascii_art.txt)"
}

function main() {
    set_bash_error_handling
    go_to_project_root_directory
    check_ssh_key

    run_linters
    run_tests

    push_code
    display_ascii_success_message
}

main "$@"
