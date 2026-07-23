#!/usr/bin/env zsh

set -euo pipefail

readonly SCRIPT_DIRECTORY=${0:A:h}
readonly SOLUTION_DIRECTORY=${SCRIPT_DIRECTORY:h}

cd "$SOLUTION_DIRECTORY" || { echo "Failed to cd to $SOLUTION_DIRECTORY" >&2; exit 1; }
echo "Working directory: $PWD"

: "${NUGET_ORG_API_KEY:?"Environment variable is not set"}"

readonly CONFIGURATION="Release"
readonly VERSION="0.3.0"
readonly FEED="https://api.nuget.org/v3/index.json"
readonly API_KEY="${NUGET_ORG_API_KEY}"

packages=(
  "Rumrunner0.BackToReality.PasswordHashing"
)

for package in "${packages[@]}"; do
  nupkg="$package/bin/${CONFIGURATION}/$package.${VERSION}.nupkg"

  if [[ ! -f "$nupkg" ]]; then
    echo "Package not found: $nupkg" >&2
    exit 1
  fi

  echo "Pushing $nupkg..."
  dotnet nuget push "$nupkg" \
    --source "$FEED" \
    --api-key "$API_KEY"
done

echo "Done"
