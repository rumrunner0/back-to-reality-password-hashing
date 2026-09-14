---
name: release
description: Release Rumrunner0.BackToReality.PasswordHashing to nuget.org — bump the version in the csproj AND Nuget/push.zsh, validate a clean Release build, commit, pack, push. The full version is always explicit and only validated, never generated. Usage — /release 0.4.0 for a stable release, /release 0.4.0-dev.20260913.1 for a dev pre-release.
disable-model-invocation: true
---

# Release

Requested release: `$ARGUMENTS`

Work from the repository root. Follow the steps in order. If any step fails, stop and report — do not improvise around a failed step, and never run the push after a failure.

## Determine and validate the full version

The full version is ALWAYS explicit in `$ARGUMENTS` — never invent, complete, or increment any part of it; only validate, and abort on any inconsistency, reporting the expected value.

- `$ARGUMENTS` is a bare version like `0.4.0` → stable release: `<VersionPrefix>` = that version, `<VersionSuffix>` = empty. Full version = the prefix (e.g. `0.4.0`). Validate the shape: exactly three dot-separated numbers with no leading zeros (`grep -E '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'`). NuGet silently normalizes anything else (`0.4.0.0`, `0.04.0`, `0.4`), so a malformed version would pack under a different filename than `push.zsh` expects and fail only AFTER the permanent Release commit.
- `$ARGUMENTS` is a dev version like `0.4.0-dev.20260913.1` → dev pre-release: prefix = the part before the first `-`, suffix = everything after it. Validate ALL of the following:
	- The suffix has exactly the shape `dev.<YYYYMMDD>.<N>` (`<N>` ≥ 1, no leading zeros).
	- `<YYYYMMDD>` is today (`date +%Y%m%d`).
	- `<N>` equals 1 + the count of existing `Release <prefix>-dev.<YYYYMMDD>.<i>` commits, counted by whole message: `git log --format=%s | grep -Ec '^Release <prefix>-dev\.<YYYYMMDD>\.[0-9]+$'` (escape the dots). The printed count is the datum: `0` with grep's exit status 1 is the expected no-matches outcome for the first dev release of a day, not a failed step. Dev iterations must be sequential within the day (no gaps, no reuse). Never count by substring — `Release 0.4.0-dev.20260913.1` is a prefix of `Release 0.4.0-dev.20260913.11`.
	- The prefix has not already been released as a stable, checked by whole message: `git log --format=%s | grep -Fx "Release <prefix>"` must match nothing. A substring check would wrongly match the dev commits of the same prefix. SemVer orders `<prefix>-dev.*` BELOW `<prefix>`, so a dev release after its stable would resolve as older than what is already published.
- Anything else (or empty) → ask the user what to release; do not guess.

## Preflight — stop and report if any check fails

1. On `main` and the working tree is clean (`git status` shows no modified or staged files). Unrelated uncommitted changes → stop and ask.
2. Check the API key without printing it: `[[ -n "$NUGET_ORG_API_KEY" ]] && echo ok || echo MISSING`. If missing in this shell, do NOT stop: the key may still exist in the user's interactive environment, and step 6 has the `!`-prefix fallback for exactly that case — tell the user push will go through that fallback and continue. Stop only if the user confirms the key is not exported anywhere.
3. Confirm the version hasn't already been released: `git log --format=%s | grep -Fx "Release <full version>"` must match nothing — match the whole commit message, never a substring (`Release 0.4.0` is a prefix of `Release 0.4.0-dev.20260913.1`, and dev iteration `.1` is a prefix of `.11`). That's the only version-ordering check — the new version does NOT need to be higher than the current csproj value (the csproj may have been pre-bumped by hand, and servicing an older line is legitimate). nuget.org rejecting duplicate versions at push time is the final backstop.
4. The strong-name key exists at `../../documents/rumrunner0_backtoreality_passwordhashing.snk` relative to the library csproj — i.e. one level above the repo root, in the `documents/` sibling of the repo directory (`<repo>/../documents/`).

## Steps

1. **Bump the version in both places.**
	- `Rumrunner0.BackToReality.PasswordHashing/Rumrunner0.BackToReality.PasswordHashing.csproj`: set `<VersionPrefix>` and `<VersionSuffix>` (leave the suffix element empty for a stable release).
	- `Nuget/push.zsh`: set `readonly VERSION="<full version>"` — this hard-coded value must always match the csproj, or push fails/publishes a stale package.
	- Verify afterwards, per file: in the csproj `<VersionPrefix>` equals the prefix and `<VersionSuffix>` equals the suffix (empty element for a stable release); in `Nuget/push.zsh` `VERSION` equals the full version. For a dev release the full string appears ONLY in push.zsh — the csproj holds it split into prefix and suffix, so a grep for the full version across both files is expected to hit just one of them.
2. **Clean** so the validation and pack come from a fresh build: `dotnet clean --configuration Release --nologo --verbosity quiet`. This removes the previous Release outputs from `bin/` and the intermediate build state from `obj/`; NuGet restore state stays and is refreshed by the implicit restore in the next step.
3. **Validate the build.** `dotnet build --configuration Release` must succeed with 0 warnings and 0 errors, and `dotnet test --configuration Release --no-build` must pass with 0 failures. Otherwise stop and report, leaving the version bump uncommitted in the working tree — do not commit, pack, or push.
4. **Commit** exactly the two bumped files, directly on `main`, with the message exactly `Release <full version>` (no other wording). Committing only after validation guarantees every `Release X.Y.Z` commit builds green.
5. **Pack.** Run `zsh Nuget/pack.zsh` (the scripts intentionally lack the executable bit — always invoke via `zsh`, never `chmod +x`) and verify the `.nupkg` for `<full version>` now exists under `Rumrunner0.BackToReality.PasswordHashing/bin/Release/`.
6. **Push to nuget.org.** Publishing is IRREVERSIBLE (a version can be unlisted but never replaced) — treat every push as permanent. Show the user the full version and ask for explicit confirmation before pushing. Then run `zsh Nuget/push.zsh`. If the key isn't visible to you, ask the user to run `! zsh Nuget/push.zsh` themselves (the `!` prefix runs it in-session with their shell environment).
7. **Push the commit.** `git push origin main`.
8. **Report**: the released version, the `.nupkg` path, and the package URL `https://www.nuget.org/packages/Rumrunner0.BackToReality.PasswordHashing/<full version>`.

If the nuget push fails after the commit was made, leave the commit in place, report the error, and let the user decide — do not revert or retry automatically. To resume once the cause is fixed, run `zsh Nuget/push.zsh` and then `git push origin main` directly — do NOT re-run `/release` for the same version (preflight 3 would refuse it because the Release commit already exists, even though nothing reached the feed).
