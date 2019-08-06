#!/bin/bash

set -eou pipefail

function go_to_project_root_directory() {
    local -r scripts_dir=$( dirname "${BASH_SOURCE[0]}")

    cd "$scripts_dir/.."
}

function configure_hooks() {
    git config core.hooksPath ./hooks
}

main() {
    go_to_project_root_directory
    configure_hooks
}

main
