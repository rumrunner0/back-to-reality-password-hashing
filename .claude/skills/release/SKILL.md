---
name: release
description: Release Rumrunner0.BackToReality.PasswordHashing to nuget.org — bump the version in the csproj AND Nuget/push.zsh, validate a clean Release build, commit, pack, push. Usage — /release 0.2.1 for a stable release, /release dev for the next dev pre-release, /release 0.3.0-dev.20260719.1 for an explicit suffixed version.
disable-model-invocation: true
---

# Release

Requested release: `$ARGUMENTS`

Work from the repository root. Follow the steps in order. If any step fails, stop and report — do not improvise around a failed step, and never run the push after a failure.

## Determine the full version

- `$ARGUMENTS` is a bare version like `0.2.1` → stable release: `<VersionPrefix>` = that version, `<VersionSuffix>` = empty. Full version = the prefix (e.g. `0.2.1`).
- `$ARGUMENTS` is `dev` → dev pre-release: keep the current `<VersionPrefix>` from the library csproj; `<VersionSuffix>` = `dev.<YYYYMMDD>.<N>` where `<YYYYMMDD>` is today (`date +%Y%m%d`) and `<N>` is 1 + the number of `Release <prefix>-dev.<YYYYMMDD>.*` commits already in `git log --oneline` for today. Full version = `<prefix>-dev.<YYYYMMDD>.<N>` (e.g. `0.3.0-dev.20260719.1`).
- `$ARGUMENTS` is a version with an explicit suffix like `0.3.0-dev.20260719.1` → prefix = the part before the first `-`, suffix = everything after it.
- Anything else (or empty) → ask the user what to release; do not guess.

## Preflight — stop and report if any check fails

1. On `main` and the working tree is clean (`git status` shows no modified or staged files). Unrelated uncommitted changes → stop and ask.
2. Verify the API key is available without printing it: `[[ -n "$NUGET_ORG_API_KEY" ]] && echo ok || echo MISSING`. If missing, tell the user to export it (it lives in their shell profile) and stop.
3. Confirm the version hasn't already been released: `git log --oneline` must contain no `Release <full version>` commit. That's the only version-ordering check — the new version does NOT need to be higher than the current csproj value (the csproj may have been pre-bumped by hand, and servicing an older line — e.g. releasing `0.2.1` while `0.3.x` exists — is legitimate). nuget.org rejecting duplicate versions at push time is the final backstop.
4. The strong-name key exists at `../../documents/rumrunner0_backtoreality_passwordhashing.snk` relative to the library csproj — i.e. one level above the repo root, in the `documents/` sibling of the repo directory (`<repo>/../documents/`).

## Steps

1. **Bump the version in both places.**
    - `Rumrunner0.BackToReality.PasswordHashing/Rumrunner0.BackToReality.PasswordHashing.csproj`: set `<VersionPrefix>` and `<VersionSuffix>` (leave the suffix element empty for a stable release).
    - `Nuget/push.zsh`: set `readonly VERSION="<full version>"` — this hard-coded value must always match the csproj, or push fails/publishes a stale package.
    - Grep both files afterwards to confirm they agree.
2. **Clean** so the validation and pack come from a fresh build: `dotnet clean --configuration Release --nologo --verbosity quiet`. This removes the previous Release outputs from `bin/` and the intermediate build state from `obj/`; NuGet restore state stays and is refreshed by the implicit restore in the next step.
3. **Validate the build.** `dotnet build --configuration Release` must succeed with 0 warnings and 0 errors. (There is no test project in this repo — if one is ever added, run `dotnet test --configuration Release --no-build` here too and require 0 failures.) Otherwise stop and report, leaving the version bump uncommitted in the working tree — do not commit, pack, or push.
4. **Commit** exactly the two bumped files, directly on `main`, with the message exactly `Release <full version>` (no other wording). Committing only after validation guarantees every `Release X.Y.Z` commit builds green.
5. **Pack.** Run `zsh Nuget/pack.zsh` (the scripts intentionally lack the executable bit — always invoke via `zsh`) and verify the `.nupkg` for `<full version>` now exists under `Rumrunner0.BackToReality.PasswordHashing/bin/Release/`.
6. **Push to nuget.org.** Publishing is IRREVERSIBLE (a nuget.org version can be unlisted but never replaced). Show the user the full version and ask for explicit confirmation before pushing. Then run `zsh Nuget/push.zsh`. If the key isn't visible to you, ask the user to run `! zsh Nuget/push.zsh` themselves (the `!` prefix runs it in-session with their shell environment).
7. **Push the commit.** `git push origin main`.
8. **Report**: the released version, the `.nupkg` path, and the package URL `https://www.nuget.org/packages/Rumrunner0.BackToReality.PasswordHashing/<version>`.

If the nuget push fails after the commit was made, leave the commit in place, report the error, and let the user decide — do not revert or retry automatically.
