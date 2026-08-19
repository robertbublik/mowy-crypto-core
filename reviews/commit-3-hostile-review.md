# Commit 3 hostile review

Status: Implemented agent review; not independent cryptographic assurance.

- Scope: canonical device-key-bundle input, Ed25519 signing and verification,
  X25519 rotation, private-key publication ordering, validity and retention,
  public SQLite pin state, rollback/equivocation behavior, and public ABI
- Reviewed: 2026-08-19
- Reviewer: implementing agent in a separate hostile pass
- Independent-review status: open; this review cannot authorize real data

## Findings

| ID | Severity | Precondition | Execution path | Impact | Remediation | Required regression | Disposition |
| --- | --- | --- | --- | --- | --- | --- | --- |
| C3-01 | High | Rotated X25519 generation calls the vendored convenience generator and the underlying C operation unexpectedly fails | The vendored method asserts success rather than returning an error | Release abort violates the expected-failure policy and can cross the intended coarse error boundary | Generate a zeroizing random seed through libsodium, then use the fallible `KeyPair::from_seed` API and map failure to `Cryptography` | Strict source scan plus rotation generation test and Clippy panic lint | Resolved |
| C3-02 | High | An attacker supplies a correctly signed low-order X25519 public key | Signature verification succeeds, but later sealing cannot establish a valid shared secret | A pinned but unusable recipient key creates avoidable denial of service and defers rejection beyond state mutation | Validate every agreement public key with libsodium X25519 scalar multiplication before signature verification or persistence | Signed bundle with an all-zero/low-order agreement input returns `InvalidInput` | Resolved |
| C3-03 | High | SQLite state is modified or corrupted after pinning | A caller loads a row and assumes the earlier import verification still applies | Tampered public key state could reach manifest sealing | Remove the unverified outward read; the repository now verifies structure, signature, low-order rejection, and active time on every returned row | Pin, reload, and reverify tests; invalid and expired writes leave prior row unchanged | Resolved |
| C3-04 | High | The service replays an older self-signed key or supplies two different same-time bundles from the pinned identity | A generic upsert replaces the current agreement selector | Senders can seal to a stale key or accept signer equivocation without a visible block | Require a strictly newer `not_before` for change, allow exact idempotent replay only, and compare identity/key/signature fields with libsodium fixed-size verification | Same-time equivocation, changed identity, invalid update, and prior-row preservation tests | Resolved |
| C3-05 | High | Rotation returns a public bundle before its new private key is durably protected | Bridge or publication succeeds and the protected-store write fails or never occurs | Other devices can seal manifests to a key this device cannot open | Make protected persistence a required trait call inside rotation; return the public bundle only after `store_new` succeeds; zeroize the key on every failure | Failing store returns no bundle and records no key; successful store precedes the returned, verified bundle | Resolved in native ordering; physical adapter connection remains commit 7 |
| C3-06 | Medium | Unsigned `u64` timestamps are placed in SQLite `INTEGER` columns or schema drift adds secret-bearing state | Values above `i64::MAX` truncate/fail, or private material enters the plain database | Canonical comparisons diverge or the at-rest boundary is weakened | Store timestamps as exact 8-byte big-endian blobs; use a strict, fixed-length, non-nil, eight-column public schema and exact-column regression | File-backed pragma/schema test, malformed-length rejection, nil rejection, and exact column list | Resolved |
| C3-07 | Medium | A validity addition or grace addition overflows, or deletion runs while an unconsumed manifest remains | Unchecked time arithmetic wraps or a coarse time-only cleanup deletes the old secret | A valid retained manifest becomes permanently unopenable | Use checked additions, exact 30-day construction, exact 7-day boundary, and require zero unconsumed references before `Delete` | Before/at boundary, nonzero reference, and `u64` overflow regressions | Resolved in policy; durable reference integration remains commits 4–6 |
| C3-08 | High | The first self-signed bundle is maliciously substituted before local pinning | P2 has no account credential binding or human verification | Trust on first use can pin an attacker identity | Name the limitation in code/evidence, never present self-signature as account identity, and defer authenticated binding plus verification value to P3 | Public ABI remains fixture-only and documentation contains no account-binding claim | Accepted package boundary; blocks stronger identity claim |
| C3-09 | Medium | A reviewer assumes a passing native test means rotated keys are already stored on both phones or bundles already cross the Expo bridge | This commit intentionally keeps the UDL unchanged | Evidence can overclaim integrated persistence or publication | Keep the module internal, keep generated bindings unchanged, and require exact-revision physical proof in commit 7/8 | Generated ABI drift check and explicit remaining-boundary section | Accepted slice boundary; blocks integration claim |

## Negative inspection

- No private key, archive key, raw root item, caller randomness, database path,
  plaintext, or cryptographic primitive is added to the UDL or generated
  Swift/Kotlin interfaces.
- The database schema contains only account/device/key identifiers, validity
  timestamps, identity/agreement public keys, and a public signature. It has no
  secret, private-key, archive-key, attachment-key, plaintext, or sealed-blob
  column.
- Authored code contains no `unwrap`, `expect`, `panic`, `todo`,
  `unimplemented`, `dbg`, stdout, or stderr formatting path.
- Fixed-size identity, key, signature, and UUID comparisons use libsodium
  constant-time operations. Public timestamp ordering uses checked ordinary
  comparison after structural validation.
- Invalid structure, low-order keys, invalid signatures, future/expired
  windows, changed identity, rollback, equivocation, storage failure, and
  overflow map to bounded enum values without platform or database detail.
- The committed deterministic seeds are visibly labeled fixture values and are
  used only to reproduce the public vector; no production identifier,
  credential, or secret enters the public repository.

C3-08 and C3-09 are explicit package boundaries, not resolved assurance.
C3-05 and C3-07 require their named integration regressions before the complete
P2 proof can be claimed. Independent implementation review remains mandatory
before any real recording.
