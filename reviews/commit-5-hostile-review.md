# Commit 5 hostile review

Status: Implemented agent review; not independent cryptographic assurance.

- Scope: envelope geometry and AAD, secretstream and digest lifecycle,
  bounded I/O, private-file operations, sender/receiver SQLite transactions,
  replay behavior, and unchanged public ABI
- Reviewed: 2026-08-19
- Reviewer: implementing agent in a separate hostile pass
- Independent-review status: open; this review cannot authorize real data

## Findings

| ID | Severity | Precondition | Execution path | Impact | Remediation | Required regression | Disposition |
| --- | --- | --- | --- | --- | --- | --- | --- |
| C5-01 | High | The 25 MiB operation ceiling is implemented inside the header-format geometry function | A future parser treats P2 policy as an envelope-v1 format limit | The committed implementation silently contradicts D28 and prevents compatible large-format inspection | Separate bounded format geometry through `u32::MAX` records from the P2 operation-policy check | Header above 25 MiB parses to canonical count while encrypt/decrypt policy still rejects it | Resolved |
| C5-02 | Critical | Plaintext is written before all records, the final tag, and EOF authenticate | A late record fails after earlier plaintext reached a destination | Partial unauthenticated plaintext could be returned, registered, or survive failure | Keep the primitive internal; verify full size/digest before plaintext, write only to one generated unpromoted temp, and delete it on every error/cancellation | Final-record corruption and cancellation after one record leave no temp and return no path | Resolved in file-store path; bridge remains blocked until commit 7 |
| C5-03 | High | The ciphertext file changes between the digest pass and authenticated-record pass | A concurrent writer races the two-pass receiver | Digest identity and decrypted bytes could refer to different snapshots | Open one regular-file descriptor, require size/digest/EOF first, then rely on per-record secretstream authentication and exact AAD/tag/EOF during the second pass; discard the temp on any disagreement | Header and every record position tamper fail, including a re-digested changed stream header | Resolved; writable package namespace compromise remains outside the service threat |
| C5-04 | High | A source path is replaced with a symlink between metadata validation and open | The core follows a link outside the package namespace | Arbitrary local file content could be encrypted or read | Compare pre-open `symlink_metadata` with post-open descriptor device/inode and reject before reading; require canonical direct namespaces and generated names | Symlink source and linked root reject; regular-file round trip succeeds | Resolved |
| C5-05 | High | A final ciphertext appears after encryption starts | A normal rename may overwrite it or publish over conflicting state | Existing ciphertext can be replaced and operation identity becomes ambiguous | Serialize package file operations and recheck the exact final path after sync immediately before rename; on conflict delete only the temp | Inject a destination during encryption, preserve its bytes, and leave no partial temp | Resolved for the package-owned single-process namespace; compromised-device concurrent writes are a residual threat |
| C5-06 | High | The stable ciphertext rename succeeds but SQLite outbox commit does not | Relaunch sees a usable file with no durable protected-message outbox | Orphan ciphertext could be mistaken for committed work or unknown stream state reused | Keep sender `encrypting` until one descriptor/outbox/state transaction commits; cleanup for that state removes both partial and stable ciphertext and restarts from the source with fresh crypto | Transaction trigger rollback plus relaunch cleanup of both ciphertext names | Resolved primitives; coordinator wiring remains commit 7 |
| C5-07 | High | SQLite inserts the sealed outbox or receiver operation but fails before its paired state/replay write | Partial durable state survives a database error | Message loss, duplicate acceptance, or replay ledger bypass | Use `IMMEDIATE` transactions with foreign keys and inject aborting triggers at the second write | Sender outbox count and receiver replay/operation counts remain zero after forced failures | Resolved |
| C5-08 | High | Receiver persistence accepts an opened manifest and an independently supplied sealed blob | Authenticated fields can be committed beside unrelated opaque transport bytes | Relaunch derives a different key or fails inconsistently | Make `OpenedManifest` retain its exact source `SealedManifest`; receiver commit accepts only that compound value | A conflicting sealed source for the same replay tuple fails, with no API parameter that can pair a different blob | Resolved |
| C5-09 | High | The same conversation/asset is delivered twice or an operation UUID is reused | Duplicate or reordered relay input reaches state creation | A second plaintext copy or conflicting descriptor can be created | Commit the tuple replay row with waiting state; exact sealed/descriptor duplicate returns the first operation, every conflicting reuse fails before mutation | Exact duplicate with a new handle resumes; changed blob, tuple, digest, or handle conflicts | Resolved for waiting state; post-archive idempotence remains commit 6 |
| C5-10 | Medium | Header length/count causes allocation or unchecked arithmetic | Hostile input declares extreme geometry | Memory exhaustion, overflow, or panic | Parse into fixed arrays, use checked format arithmetic, allocate only one fixed maximum ciphertext record, and apply P2 policy before operation | 64-case arbitrary header input plus exact format maximum and overflow boundary | Resolved |
| C5-11 | Medium | Short reads/writes, disk full, cancellation, or process relaunch occur around file creation | Standard I/O does not complete an entire requested buffer | Silent truncation, a returned partial path, or broad cleanup | Use `read_exact`/`write_all`, sync before publication, generated exact cleanup targets, and coarse errors | Choppy I/O round trip, disk-full failure, partial cancellation, and exact orphan cleanup | Resolved |
| C5-12 | Medium | Reviewers assume plain SQLite holds the opened manifest or attachment key | Schema names include public plaintext length and recipient key ID | Secret-at-rest claims become untestable or misleading | Persist only public descriptors and the opaque 408-byte sealed blob; keep the 128-byte opened manifest in a non-cloneable zeroizing owner | Strict-schema inspection forbids attachment/archive/private keys, opened manifest, and plaintext bytes | Resolved |
| C5-13 | Low | Predictable UUID-derived names let an existing entry block progress | A stale or locally planted file occupies the exact destination | Denial of service | Fail closed without replacement and require state-guided cleanup of only exact regular files | Existing destination and non-regular/link entries are preserved and rejected | Accepted fail-closed behavior |

## Negative inspection

- The UDL and generated bindings remain unchanged. No private key, attachment
  key, opened manifest, plaintext buffer, caller randomness, arbitrary path,
  SQL string, raw encrypt/decrypt primitive, or unbounded error crosses UniFFI.
- SQLite contains public UUIDs, lengths, digests, generated filenames, state,
  timestamps, selectors, and opaque sealed ciphertext only. It has no secret
  column or opened-manifest serialization.
- The attachment key and decoded manifest are non-cloneable zeroizing owners.
  Plaintext chunks returned by libsodium are immediately wrapped in
  `Zeroizing`; no secret-bearing type implements `Debug` or display.
- Authored source has no `unwrap`, `expect`, `panic`, `todo`, `unimplemented`,
  `dbg`, stdout, or stderr path. Expected failures are bounded enums.
- Fixed UUIDs/digests/sealed blobs use libsodium comparisons where equality is
  security-relevant; public geometry, versions, state integers, and filenames
  use checked ordinary comparisons.

C5-02, C5-06, and C5-09 retain their named later integration/archive work.
Independent review of the completed implementation remains mandatory before
real recordings or any encryption claim.
