#!/usr/bin/env bash

function set_bash_error_handling() {
    set -euo pipefail
}

function go_to_project_root_directory() {
    local -r script_dir=$( dirname "${BASH_SOURCE[0]}")

    cd "$script_dir/.."
}

function clean_old_autodocs() {
    ./gradlew :backends:credhub:clean
}

function generate_documentation_snippets_from_controller_tests() {
    ./gradlew :backends:credhub:test --tests -- *Controller*
}

function build_autodoc_html() {
  ./gradlew buildAndCopyRestDocsIntoSpringStaticAssetLocation -x check -x test
}

function main() {
    set_bash_error_handling
    go_to_project_root_directory

    clean_old_autodocs
    generate_documentation_snippets_from_controller_tests
    build_autodoc_html
}

main
