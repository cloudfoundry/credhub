#!/bin/bash

VERSION_FILE=""

function set_bash_error_handling() {
  set -euo pipefail
}

function get_version_file() {
  local -r script_dir="$( cd "$( dirname "${BASH_SOURCE[0]}")"/.. && pwd )"
  VERSION_FILE="$script_dir/src/main/resources/version"
}

function use_credhub_version_if_available() {
  local -r credhub_version=${CREDHUB_SERVER_VERSION:-}
  if [[ -n ${credhub_version} ]]; then
    echo "$credhub_version" > "$VERSION_FILE"
    display_version
    exit 0
  fi
}

function display_version() {
  echo "Using version $(cat "$VERSION_FILE")"
}

function overwrite_version_file() {
  local -r version=$1
  local -r version_with_dev_suffix=${version//x/0-dev}
  echo "$version_with_dev_suffix" > "$VERSION_FILE"
}

function use_version_from_branch_if_available() {
  local -r current_branch=$(git branch | grep '\*' | cut -d ' ' -f2)

  if [[ "$current_branch" =~ ^[0-9]*.[0-9]*.x$ ]]; then
    overwrite_version_file "$current_branch"
    display_version
  elif [[ "$current_branch" =~ master ]]; then
    local -r highest_local_version=$(git branch | grep -o "[0-9]*\\.[0-9]*\\.x" | sort -n | tail -1)
    overwrite_version_file "$highest_local_version"
    display_version
  else
    local -r yellow_color="\\033[00;33m"
    echo -e "${yellow_color}\\n\\n\\n\\n\\n\\n********"
    echo -e "You are on a feature branch so you must manually update the version file."
    display_version
    echo -e "********\\n\\n\\n\\n\\n\\n"
  fi
}

function main() {
  set_bash_error_handling
  get_version_file
  use_credhub_version_if_available
  use_version_from_branch_if_available
}

main "$@"
