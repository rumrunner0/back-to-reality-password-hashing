# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

.NET solution with the class library `Rumrunner0.BackToReality.PasswordHashing` (Argon2id password hashing with a PHC-formatted string API, published to nuget.org) and a `...PasswordHashing.Demo` console app. There is NO test project and no CI: `dotnet build` is the verification step, and the build must stay at 0 warnings (missing XML docs on public members produce warnings). If a test project is ever added, `dotnet test` becomes part of verification and the `/release` skill must be updated to run it.

## Gotchas

- The release version lives in TWO places that must stay in sync: `<VersionPrefix>` in `Rumrunner0.BackToReality.PasswordHashing/Rumrunner0.BackToReality.PasswordHashing.csproj` and `VERSION=` in `Nuget/push.zsh`. Do not add `<AssemblyVersion>`/`<FileVersion>` back — they derive from the version prefix.
- Assemblies are strong-named with a key outside the repo (`../documents/rumrunner0_backtoreality_passwordhashing.snk` relative to the repo root, gitignored) — a fresh clone won't build without it.
- Cross-project MSBuild config (target framework `net9.0`, language settings, build matrix, assembly metadata) lives in `Directory.Build.props`; packaging, versioning, strong naming, and doc generation live in the library csproj.
- Package versions are centralized (`Directory.Packages.props`, CPM): a `PackageReference` must not carry `Version`; add a `PackageVersion` entry there instead.
- `ImplicitUsings` is disabled — every file lists explicit `using` directives.
- The Demo project explicitly opts out of packing, signing, and doc generation (`IsPackable`/`SignAssembly`/`GenerateDocumentationFile` all `false`) — keep it that way.
- Old `.nupkg`/`.snupkg` files accumulate in `bin/Release` across releases: `dotnet clean` only deletes recorded build outputs, and `Pack` never registers its packages there. This is expected and accepted — NEVER delete them (no `rm`, no cleanup steps in scripts). `Nuget/push.zsh` picks the exact file by version, so stale packages are harmless.

## Releases

Use `/release <version>`. Manual flow: bump the version in both places above → `dotnet clean --configuration Release` → verify a clean `dotnet build --configuration Release` with 0 warnings → commit `Release X.Y.Z` → `zsh Nuget/pack.zsh` → `zsh Nuget/push.zsh` (needs `NUGET_ORG_API_KEY`, exported in the shell profile). The scripts intentionally lack the executable bit — always invoke them via `zsh`, never `chmod +x`. A pushed version can never be overwritten on nuget.org.

## Code style

Style is codified in `.editorconfig`. Check with `dotnet format style --verify-no-changes`; NEVER run plain `dotnet format` or `dotnet format whitespace` — Roslyn has no option for the `new (` spacing rule and strips the space before target-typed `new` parentheses (`return new (args);`). Key points:

- Tabs for indentation; Allman braces. Single-line guard clauses stay unbraced on one line.
- File-scoped namespaces mirroring the feature folder (e.g. `Rumrunner0.BackToReality.PasswordHashing.Argon2`).
- Private constants in SCREAMING_SNAKE_CASE (e.g. `SALT_LENGTH`); private static fields prefixed `_`.
- XML doc comments (`///`) on every member, including private ones.
- Classes are `sealed` unless designed for inheritance.
- Multi-line call argument lists put the opening `(` on its own line.

## Git

Commit directly to `main` — no feature branches, PRs, or tags. Messages are short and sentence-case (`Added X`, `Fixed Y`, `Improved Z`); releases are `Release X.Y.Z`; unstable APIs are flagged `(EXPERIMENTAL)` in the commit message.
