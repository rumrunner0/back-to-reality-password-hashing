#!/bin/sh

# Claude Code Stop hook: blocks Claude from finishing a turn while `dotnet build` fails.
# - Always builds, non-incrementally: timestamp-skip heuristics false-green deletions and
#   renames (mtime survives both), and an up-to-date compile skip would hide warnings that
#   an earlier plain build already tolerated — --no-incremental forces the compiler to run
#   (measured ~0.8s on this solution).
# - Warnings block too (-warnaserror): the repo's contract is a 0-warnings build.
# - Loop guard: if a block already triggered a fix attempt this turn (stop_hook_active), notifies the user via systemMessage (naming the current top error) instead of blocking again.
# - Fail-open: environment problems (bad cwd, missing jq, missing dotnet, missing strong-name key) disable the gate instead of trapping Claude.

input=$(cat)
cd "${CLAUDE_PROJECT_DIR:-$(dirname "$0")/../..}" || exit 0

# jq is required for the loop guard and for emitting safely escaped JSON.
# Without it, both silently fail and the gate just disappears.
if ! command -v jq >/dev/null 2>&1; then
  printf '{"systemMessage":"Build gate disabled: jq not found on PATH."}'
  exit 0
fi

# A machine without the SDK cannot build at all; blocking would trap Claude with an unfixable reason.
if ! command -v dotnet >/dev/null 2>&1; then
  printf '{"systemMessage":"Build gate disabled: dotnet not found on PATH."}'
  exit 0
fi

# The strong-name key lives outside the repo; without it the library cannot build on this machine.
if [ ! -f ../documents/rumrunner0_backtoreality_passwordhashing.snk ]; then
  printf '{"systemMessage":"Build gate disabled: strong-name key not found at ../documents."}'
  exit 0
fi

# Forces English so the ': error' filter below matches regardless of SDK locale.
# -warnaserror enforces the 0-warnings contract, not just compilability.
if output=$(DOTNET_CLI_UI_LANGUAGE=en dotnet build --nologo --verbosity quiet --no-incremental -warnaserror 2>&1); then
  exit 0
fi

# A block this turn already made Claude attempt a fix; don't loop and hand off to the user,
# naming the current top error (it may differ from the first block's reason precisely because a fix was attempted).
if printf '%s' "$input" | jq -e '.stop_hook_active == true' >/dev/null 2>&1; then
  first_error=$(printf '%s' "$output" | grep -iE ': error' | awk '!seen[$0]++' | head -n 1)
  [ -z "$first_error" ] && first_error=$(printf '%s' "$output" | tail -n 1)
  printf '%s' "$first_error" | jq -Rs '{systemMessage:("Build gate: dotnet build is STILL failing after a fix attempt: " + .)}'
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