#!/bin/bash

set -euo pipefail

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
VERSION_FILE="$DIR/src/main/resources/version"

branch=$(git show-ref --heads | grep `git rev-parse HEAD` | cut -d ' ' -f2 | cut -d '/' -f3)

if [[ $branch =~ ^[0-9]*.[0-9]*.x$ ]]; then
  echo "$branch" | sed 's/x/0-dev/' > "$VERSION_FILE"
  echo "Version file has been updated."
elif [[ $branch =~ master ]]; then
  version=$(git branch | grep -o "[0-9]*\.[0-9]*\.x" | sort -n | tail -1)
  echo "$version" | sed 's/x/0-dev/' > "$VERSION_FILE"
  echo "Version file has been updated."
else
  echo "0.0.0" > "$VERSION_FILE"
  echo "****You are on a feature branch so you must manually update the version file.****"
fi
