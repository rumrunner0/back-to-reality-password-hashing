#!/bin/sh

# Claude Code Stop hook: blocks Claude from finishing a turn while `dotnet build` fails.
# - Incremental: skips the build when no watched file changed since the last SUCCESSFUL build.
# - Loop guard: if a block already triggered a fix attempt this turn (stop_hook_active), notifies the user via systemMessage instead of blocking again.
# - Fail-open: environment problems (bad cwd, missing jq) disable the gate instead of trapping Claude.

input=$(cat)
cd "${CLAUDE_PROJECT_DIR:-$(dirname "$0")/../..}" || exit 0

# jq is required for the loop guard and for emitting safely escaped JSON.
# Without it, both silently fail and the gate just disappears.
if ! command -v jq >/dev/null 2>&1; then
  printf '{"systemMessage":"Build gate disabled: jq not found on PATH."}'
  exit 0
fi

stamp=".claude/.build-stamp"

# Skips the build if nothing relevant changed since the last successful build.
# Not `find -quit`: non-portable, and its failure mode here is a silent permanent skip.
if [ -f "$stamp" ]; then
  changed=$(find . \( -name bin -o -name obj -o -name .git \) -prune -o \
    \( -name '*.cs' -o -name '*.csproj' -o -name '*.props' \
       -o -name '*.targets' -o -name '*.sln' \) \
    -newer "$stamp" -print 2>/dev/null | head -n 1)
  [ -z "$changed" ] && exit 0
fi

# Forces English so the ': error' filter below matches regardless of SDK locale.
if output=$(DOTNET_CLI_UI_LANGUAGE=en dotnet build --nologo --verbosity quiet 2>&1); then
  mkdir -p .claude 2>/dev/null
  touch "$stamp" 2>/dev/null
  exit 0
fi

# A block this turn already made Claude attempt a fix; don't loop and hand off to the user.
if printf '%s' "$input" | jq -e '.stop_hook_active == true' >/dev/null 2>&1; then
  printf '{"systemMessage":"Build gate: dotnet build is STILL failing after a fix attempt."}'
  exit 0
fi

# Prefers MSBuild diagnostic lines (path(line,col): error CSxxxx: ...).
# Falls back to the raw tail for failures that emit none (missing SDK, MSB1011 multiple projects, crash).
# Dedupes first: multi-targeted builds repeat identical diagnostics per TFM and would otherwise waste the 40-line cap.
errors=$(printf '%s' "$output" | grep -iE ': error' | awk '!seen[$0]++' | head -n 40)
[ -z "$errors" ] && errors=$(printf '%s' "$output" | tail -n 40)

printf '%s' "$errors" \
  | jq -Rs '{decision:"block", reason:("dotnet build failed. Fix the errors before finishing:\n" + .)}'

exit 0