#!/usr/bin/env zsh

set -euo pipefail

readonly SCRIPT_DIRECTORY=${0:A:h}
readonly SOLUTION_DIRECTORY=${SCRIPT_DIRECTORY:h}

cd "$SOLUTION_DIRECTORY" || { echo "Failed to cd to $SOLUTION_DIRECTORY" >&2; exit 1; }
echo "Working directory: $PWD"

readonly CONFIGURATION="Release"

dotnet pack --configuration ${CONFIGURATION}

echo "Done"