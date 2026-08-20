# Commit 12 disposable iOS proof-output cleanup

Status: The exact development-only receiver proof app used for the commit-10
physical relock run and its private app container were removed after evidence
inspection. An exact bundle query then verified that the app was absent. The
retained encrypted receiver archive and disposable proof database were removed
with the app-private container under iOS uninstall semantics. No separate
post-uninstall filesystem inventory was performed.

- Package: P2 sealed envelope foundation
- Requirement: `M2-ASSURANCE-01`
- Recorded: 2026-08-20

## Reviewable outcome

Commit 10 recorded the successful terminal receiver state before cleanup: one
regular protected archive existed, while the source, ciphertext,
receive-temporary, and verified-plaintext namespaces were empty. Retaining
that archive briefly made the terminal state independently inspectable, but it
did not satisfy the private P2 contract that disposable proof output is
deleted at the end of the run.

After the documentation review identified that gap, the maintainer kept the
physical iPhone connected and unlocked. The cleanup selected exactly one
installed app by the fixed development proof bundle identifier, removed that
app, and repeated the same exact bundle query. The normalized results were:

| Check | Result |
| --- | --- |
| Exact development proof app before cleanup | one match |
| Exact development proof app removal | succeeded |
| Exact development proof app after cleanup | zero matches |

Under iOS uninstall semantics, removing the app removes its private application
container, including the protected receiver archive, SQLite proof database,
its sidecars, and the fixed proof namespaces. The reviewed proof app uses that
private `Application Support` hierarchy and declares no App Group container.
The removal therefore also covers proof-database rows and sidecars that could
have survived the discarded self-contained relock attempt described in commit
10. The separate temporary sender container had already been removed after its
own exact cleanup. No product application, unrelated user data, recording,
account, service credential, or unrelated container was targeted.

The development proof app is reproducible from the reviewed source and can be
rebuilt and reinstalled. The deleted container output is not recoverable: no
copy of the removed container, archive, or database was retained. Only the
reviewed app and public deterministic fixture can be regenerated.

This later container reset does not prove that database cleanup completed at
the moment the discarded self-contained attempt returned `STORAGE`; commit
10's historical classification remains unchanged. It also does not claim that
the development Keychain access group was erased. The receiver's persistent
development device root is identity material rather than fixture output and
is governed by the separate protected-key lifecycle. The temporary sender's
exact disposable Keychain item had already been deleted before its temporary
app was uninstalled.

## Evidence boundary

The device selection and bundle query were consumed only as local execution
inputs. Durable evidence records fixed counts and the normalized outcome, not
the device identifier, serial, assigned name, CoreDevice identifier, signing
identity, email, certificate fingerprint, team, provisioning profile, local
container path, or raw device-tool output.

No production Rust, Swift, Kotlin, ABI, binding, byte format, cryptographic
operation, storage transition, or product surface changed. This commit only
records final cleanup of the disposable physical proof environment and
corrects the current documentation so temporary evidence retention cannot be
mistaken for permanent retention.

## Validation

Two complete `scripts/check.sh` invocations exited zero after every pinned tool
path was supplied. Each passed 83 Rust tests, the fuzz-target compile, all four
mobile Rust release targets, signed-source and build-script inventories,
generated bindings and SBOM, four Swift tests, five Android tests and lint,
cargo-deny policy, and a clean 83-test rebuild while the operating system
denied network access. The known offline advisory-index warnings and unused
NCSA allowance warning were unchanged.

Three preceding invocations were retained as setup evidence rather than
silently discarded. The first passed 83 Rust tests and the fuzz compile, then
stopped before mobile builds because the task-specific Android NDK variable
was omitted. The second again passed those checks, then paired the temporary
mobile Cargo with the default compiler and stopped because the iOS target
libraries were not selected. The third passed 83 Rust tests, the fuzz compile,
all four mobile release targets, signed-source verification, generated
bindings, and the SBOM, then stopped at the platform gate because the default
Gradle was 8.12 rather than the pinned 8.14.3 distribution. The fourth
invocation supplied the matching compiler, NDK, Gradle, and supply-chain tools
explicitly and exited zero. After the cleanup-claim wording and hostile review
were finalized, a fifth invocation repeated the complete gate and exited zero
on that exact tree. None of the three setup failures was treated as a passing
gate.

`git diff --check` passed. A category-only scan of the tracked and new current
tree found none of the local device/signing identifier classes removed in
commit 11; candidate values were not printed into the audit result.

## Remaining gates

This cleanup does not close the hazardous real-device disk-full/rename/kill
matrix, the separately authorized published-history/cache remediation from
commit 11, or independent human review. Those remain explicit handoff and
release gates.
