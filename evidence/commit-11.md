# Commit 11 public evidence identifier hygiene

Status: The current project-owned source and evidence tree omits local device
and signing identifiers. Older public Git objects and downstream caches remain
an explicit external-remediation item; this append-only commit does not claim
to erase them.

- Package: P2 sealed envelope foundation
- Requirement: `M2-ASSURANCE-01`
- Recorded: 2026-08-20

## Reviewable outcome

A post-commit-10 evidence-boundary audit found local device/signing metadata in
two historical evidence pages and a development-team value in the proof-app
Xcode project. The current tree now:

1. retains only normalized device model/OS, artifact hash, and pass/fail fields
   in the commit-2 physical-results table;
2. replaces signing identity, email, certificate fingerprint, team,
   provisioning-profile, team-prefixed application, and device identifiers
   with a statement that local automatic development signing was verified;
3. removes both committed `DEVELOPMENT_TEAM` assignments from the proof-app
   project; and
4. requires signed physical builds to supply the team only through local Xcode
   state or the task-specific `MOWY_P2_APPLE_TEAM` command-line value.

The audit distinguishes public device model names and ordinary artifact
SHA-256 evidence from local identifiers. It also leaves upstream package-author
metadata in the generated SBOM intact; those fields are dependency provenance,
not maintainer signing metadata.

No cryptographic code, ABI, generated binding, byte format, Keychain class,
file-protection class, durable transition, receipt, or product surface changes.
Generic unsigned iOS builds remain independent of a local team value.

## Validation

The exact current tree is checked for formatting, deterministic tests, all four
mobile targets, generated binding/source/SBOM drift, platform tests and lint,
supply-chain policy, and the operating-system-network-denied clean rebuild by
the normal `scripts/check.sh` gate. The first post-redaction invocation omitted
the Android SDK location and stopped at the platform gate after 83 passing Rust
tests, all four mobile Rust targets, signed-source verification, generated
binding drift, and the SBOM check. The corrected invocation supplied the same
pinned toolchain plus the SDK location and exited zero: 83 Rust tests, all four
mobile release targets, four Swift tests, five Android tests and lint,
source/signature/build-script/binding/SBOM checks, cargo-deny, and the clean
operating-system-network-denied rebuild all passed. The previously documented
offline advisory-index and unused NCSA allowance warnings remain unchanged.

An unsigned generic-iOS Release build then compiled and linked the proof app
with both code-signing switches disabled and no development-team override,
proving the committed project no longer depends on a personal team value. A
separate category-only audit passed: project-owned evidence and build settings
retain none of the local identifier classes listed above, and candidate values
were never printed into the audit result.

## Published-history boundary

The affected earlier commits were already public before this correction.
Removing values from the branch tip does not remove reachable Git objects,
forks, clones, pull-request caches, or hosting-provider caches. Rewriting the
published branch, coordinating cache removal, and notifying downstream users
are destructive/external actions and require explicit maintainer authorization
and a reviewed execution plan. Until then, the PR and handoff must state this
limitation and must not describe the public evidence history as clean.

## Subsequent commit-13 remediation state

The maintainer subsequently authorized the bounded rewrite, and a replacement
history has been prepared locally. The rewrite is deliberately limited to the
public core history reachable from `main`,
`package/026-p2-sealed-envelope-foundation`, and
`package/026-p2-sealed-envelope-foundation-implementation`: it normalizes the
project author's and committer's public Git metadata, applies the commit-11
identifier/team-setting redactions at their original historical locations, and
updates only the evidence baseline hashes made stale by the rewrite. It changes
no Rust, Swift, Kotlin, UDL, generated binding, vector, dependency, build
policy, or cryptographic behavior.

This is not yet remote erasure. The three repository-controlled branches have
not yet been replaced and freshly validated at their final remote heads.
Public-core PR #1 and closed draft PR #2 retain GitHub-owned references or
cached views that a force-push cannot remove; GitHub Support must dereference
those PRs and remove eligible cached views after the branch update. Private
application PR #7 is not part of the history rewrite and requires only updated
body/documentation links to the replacement hashes.

The remote inventory found no forks, releases, Actions artifacts, or Actions
caches. Independent clones and GitHub object/PR caches remain outside that
observation. Rewritten object IDs do not inherit signatures, attestations,
checks, approvals, or links attached to the old IDs. The exact replacement map
and pending completion evidence are recorded in `evidence/commit-13.md`.
