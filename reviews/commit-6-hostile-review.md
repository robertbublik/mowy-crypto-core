# Commit 6 hostile review

Status: Implemented agent review; not independent cryptographic assurance.

- Scope: archive encryption and verification, proof-object boundary, receiver
  file/database ordering, replay after sealed erasure, expiry, cleanup, and
  unchanged public ABI
- Reviewed: 2026-08-19
- Reviewer: implementing agent in a separate hostile pass
- Independent-review status: open; this review cannot authorize real data

## Findings

| ID | Severity | Precondition | Execution path | Impact | Remediation | Required regression | Disposition |
| --- | --- | --- | --- | --- | --- | --- | --- |
| C6-01 | Critical | Any sibling module can construct the type accepted by the `available` commit | Code creates an archive descriptor without opening and comparing the archive | The sealed blob and attachment key can be erased for an unverified or absent archive | Make `VerifiedArchive` fields private and allow only the archive verifier to construct it; accept that proof type in `commit_available` | Archive creation/open succeeds, while transaction code has no descriptor-only commit API | Resolved |
| C6-02 | Critical | Transport material is erased before durable archive verification | Archive encryption, sync, authentication, comparison, or rename fails late | The only key and plaintext needed to recover the recording are lost | Encrypt a private partial, open the same archive, compare against the original with exact EOF, sync/rename/validate, then commit `available` and erasure | Wrong key, wrong identifier, tamper, changed plaintext, I/O/cancellation, and transaction-fault paths never produce `available` | Resolved |
| C6-03 | High | The process dies after SQLite commits `available` but before transport-file deletion | Database and filesystem cannot share one atomic transaction | Plaintext/ciphertext can remain in the app-private container across a crash despite the internal available state | Return no path until exact cleanup; on every available relaunch load by operation handle, delete exact transport names, then require the archive file before returning | Inject crash after available commit and prove recovery deletes transport without an opened manifest or attachment key | Resolved with an explicit cross-resource window; physical device inspection remains commit 7/8 |
| C6-04 | High | Exact replay arrives after the sealed blob has been erased | Equality logic compares only public lengths/digest or attempts to retain the opened manifest | A conflicting attachment key can be accepted, or transport key material remains indefinitely | Persist only SHA-256 of all exact manifest bytes and compare it in constant time with the replay's authenticated manifest | Same manifest resealed to the same selector resumes the original available operation; any changed manifest fails | Resolved; the high-entropy one-way fingerprint is disclosed in evidence |
| C6-05 | High | Re-encryption reuses a long-lived archive key | A static stream header/nonce is reused for two archive entries | XChaCha20-Poly1305 confidentiality and integrity can fail catastrophically | Let libsodium initialize a fresh secretstream header internally for every archive and expose no caller-header constructor | Two archives of identical bytes under one key have different headers and ciphertext | Resolved |
| C6-06 | High | The verified plaintext changes between archive encryption and archive comparison | A writable package namespace or local race mutates the source file | The durable archive can represent different bytes from the file believed verified | Keep one opened regular-file descriptor, rewind it, compare every decrypted chunk with libsodium `sodium_memcmp`, and require original EOF | A source that mutates on rewind fails authentication and produces no proof | Resolved; compromised unlocked-device writes remain a residual threat |
| C6-07 | High | Archive verification succeeds but the available SQL update aborts | Disk/database failure occurs after archive publication | An orphan archive can be mistaken for committed playback or sealed material can be erased partially | Use one immediate constrained update for state, descriptor, and sealed erasure; retain `verified_temp` on failure and remove exact archive names during retry/relaunch | Aborting trigger leaves sealed blob, verified state, and no stored archive descriptor | Resolved |
| C6-08 | High | Relaunch observes temp/final/archive combinations around non-atomic renames | Crash occurs after decrypt, state mark, plaintext promotion, archive rename, or available commit | Uncertain plaintext or archive output can be trusted or returned | Implement D24's exact state matrix; delete uncertain final/archive output and decrypt fresh, but fail unavailable on missing/extra state | Crash injection at every named transition plus explicit missing-verified-temp failure returns no premature path | Resolved |
| C6-09 | High | Waiting cleanup searches a directory or accepts an arbitrary caller path | A forged entry, link, or unrelated asset shares a namespace | Cleanup can delete unrelated or attacker-selected files | Return exact expired operation/asset IDs from the transaction, derive fixed UUID names, reject links/non-regular entries, and require an exact unavailable handle for retry | Exact 24-hour boundary and retry tests remove only the named asset; unknown handle conflicts | Resolved |
| C6-10 | Medium | Archive key state is missing, corrupt, or unavailable while protected data is locked | Playback or receiver completion asks the native bridge to load the archive key | A fallback key, regeneration, detailed error, or unusable archive could be returned | Keep archive operations native and require commit 7's platform loader/relock checks to map every condition to coarse unavailable without mutation | Platform tests for missing/corrupt/locked key plus relock before promotion/commit | Open integration item for commit 7; no bridge exists in this commit |
| C6-11 | Medium | Reviewers equate application-level deletion with physical media erasure | Flash translation, snapshots, or filesystem history retain deleted blocks | Evidence overstates forensic erasure guarantees | Claim logical app-private lifetime only; rely on platform data protection and backup exclusion, not overwrite claims | Container/backup inspection after available and locked-device checks | Accepted residual; platform evidence remains commit 7/8 |
| C6-12 | Medium | A database created by an earlier unreleased development commit has the old receiver-state constraint | The newer crate opens that path because `CREATE TABLE IF NOT EXISTS` does not migrate it | The available transition fails closed and physical proof cannot complete | Commit 7 must use the new proof namespace/schema or add an explicit versioned migration before opening any retained development state; never silently drop a deployed database | Open an old-schema fixture and prove an explicit incompatible/migrated outcome before retained state is supported | Open integration item; no product or physical bridge database exists yet |
| C6-13 | Low | A predictable UUID-derived archive name already exists | A stale or locally planted entry blocks archive publication | Denial of service | Use create-new, reject replacement, remove only state-proven regular orphans, and restart from verified transport state | Existing archive destination is preserved/rejected; exact orphan cleanup is idempotent | Accepted fail-closed behavior |

## Negative inspection

- The UDL, generated bindings, dependency lock, and SBOM remain unchanged. No
  archive key, attachment key, opened manifest, plaintext buffer, arbitrary
  path, SQL string, raw archive primitive, or caller randomness crosses
  UniFFI.
- Plain SQLite retains public UUIDs, lengths, digests, generated filenames,
  timestamps, selectors, state, the opaque sealed blob only while unconsumed,
  and a manifest fingerprint. It contains no private key, archive key,
  attachment key, opened manifest, or plaintext bytes.
- Archive and attachment keys plus decoded manifests are non-cloneable
  zeroizing owners. `complete_or_recover` consumes the opened manifest, and
  only the archive verifier can construct the proof accepted by the available
  transition.
- Authored source has no `unwrap`, runtime `expect`, `panic`, `todo`,
  `unimplemented`, `dbg`, stdout, or stderr path. Expected failures are bounded
  enums.
- Security-relevant fixed digests, manifest fingerprints, UUIDs, and plaintext
  comparison use libsodium constant-time operations. Public geometry, state,
  timestamps, filenames, and versions use checked ordinary comparison.

C6-03 names the unavoidable file/SQLite boundary without treating it as one
fictional transaction. C6-10 and C6-12 are bridge-integration gates, not
claims satisfied by this internal slice. Independent review of the completed
implementation remains mandatory before real recordings or any encryption
claim.
