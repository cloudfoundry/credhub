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

function login_to_local_credhub(){
   echo "Logging in to CredHub"
   credhub a https://localhost:9000 --skip-tls-validation
   credhub l -u credhub -p password
}

function check_for_local_server(){
   echo "Checking for locally running server"
   if curl -s https://localhost:9000/health --insecure > /dev/null; then
      echo "Found locally running CredHub"
   else
      echo "CredHub is not running, please run the server and try again"
      exit
   fi
   login_to_local_credhub
}

function run_tests() {
  export GOPATH=~/go
  pushd ${GOPATH}/src/github.com/cloudfoundry-incubator/credhub-acceptance-tests
      ./scripts/run_tests.sh
  popd
}

function kill_xterm(){
  pkill xterm
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
    check_for_local_server

    run_linters
    run_tests

    push_code
    display_ascii_success_message

    kill_xterm
}

main
