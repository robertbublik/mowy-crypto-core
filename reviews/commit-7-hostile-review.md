# Commit 7 hostile review

Status: Implementing-agent review of the bridge and physical proof; not
independent cryptographic assurance and not package completion.

- Scope: UniFFI semantics, protected-store callback, platform namespaces,
  schema migration, relock/cancellation/concurrency behavior, proof apps,
  physical runs, signing/linkage, memory measurement, logs, and cleanup
- Reviewed: 2026-08-19
- Independent-review status: open; the maintainer's own cybersecurity
  verification is useful context but is not a separate reviewer under D27

## Findings

| ID | Severity | Precondition | Execution path | Impact | Remediation | Required regression | Disposition |
| --- | --- | --- | --- | --- | --- | --- | --- |
| C7-01 | Critical | The self-contained proof is mistaken for the approved two-device result | One device publishes, seals to itself, opens, and archives without an untrusted relay or recipient restart | P2 could be marked complete without interoperability, routing, or recipient durability evidence | Keep the package open; add only a separately reviewed semantic publish/send/receive ABI, then execute A→B and B→A with restart | Device B publishes; A produces sealed blob/ciphertext only; B imports durable state, restarts, opens, archives, and cleans; reciprocal direction passes | **Open; blocks completed-package merge** |
| C7-02 | High | A general caller gains access to generated protected-store callbacks | The 96-byte root item is passed as twelve `u64` values between Rust and Swift/Kotlin | A wider bridge could export persistent identity, agreement, and archive secrets | Treat callbacks as platform TCB, expose no Expo/JavaScript registration, use tokenized load, zeroize buffers/word arrays, and keep the UDL under generated-diff review | ABI scan proves no general key/bytes call; platform buffers clear on success and failure; JS inventory contains no core binding | Mitigated in this slice; independent reviewer must assess whether the TCB is acceptably narrow |
| C7-03 | High | The platform callback returns a forged or linked root path | A compromised/wrong adapter points Rust outside the fixed private namespace | Proof files or database could overwrite/read attacker-selected files | Platform derives one fixed app-private root; Rust canonicalizes it, rejects links and wrong modes/types, and derives every child name itself | Symlink/file namespace tests fail unavailable; no API accepts a caller child path | Resolved for the current proof |
| C7-04 | High | Protected data becomes unavailable after decrypt but before promotion/archive/return | User locks device during a long maximum fixture | Plaintext can be promoted or an archive path can escape after the key class becomes unavailable | Recheck availability at entry, before plaintext promotion, before/after archive work, and before return; remove uncertain plaintext/archive artifacts on relock | Deterministic `LockAfter` tests at transition boundaries plus physical mid-operation lock on each OS | Rust transition regression and Huawei launch-locked proof pass; **physical iOS mid-operation lock open** |
| C7-05 | High | A previous development database is opened by the new bridge | Schema from commit 4–6 has `user_version=1`; unknown state may also exist | Silent recreation could erase evidence; blind reuse could violate constraints | Explicitly accept only versions 1 and 2 when operation tables exist; migrate v1 by additive public table; reject every other/unversioned operation schema | Seed v1 sender/outbox row survives v2 open byte-for-byte; unknown version fails storage | Resolved |
| C7-06 | High | Proof cancellation or error occurs after source/ciphertext/database creation | Activity is destroyed, callback errors, storage fails, or auth fails | Partial plaintext/ciphertext or sealed state survives a reported failure | Run exact operation, bundle, and asset cleanup for every result; return cleanup failure instead of success; never scan broadly | Cancellation/concurrency/invalid-input tests plus post-result namespace inventory | Resolved for deterministic and successful physical paths; kill matrix remains commit 8 evidence |
| C7-07 | High | Two proof calls enter simultaneously | UI lifecycle or hostile caller invokes the operation twice | Shared deterministic namespace and database operations race | One non-blocking process lock returns coarse conflict to the second call; platform token rejects overlapping root loads | Concurrent-entry regression returns one conflict without partial success | Resolved |
| C7-08 | Medium | Memory baseline is sampled before one-time bridge initialization | First Android JNA/native call allocates retained runtime state | A compliant steady state appears to violate the 20 MiB cleanup bound, or a later report hides the failure | Run exactly one maximum warmup, then sample settled baseline and 1–10 measured cycles | Preserve the original failing measurement and require repeated settled run on both devices | Resolved; failed and corrected values are both recorded |
| C7-09 | Medium | Public proof receipt is confused with secret-free binary/process state | Receipt contains random IDs, lengths, and ciphertext/archive hashes | Metadata can be overinterpreted or logged by a later caller | Keep receipt app-private, do not log, document fields as public fixture evidence, and return no path or key | Static log scan plus source review of both publish functions | Resolved for proof apps |
| C7-10 | Medium | Android launcher activity is exported, as required for its launcher filter | Another local app invokes the development-only activity with 1–10 cycles | Local denial of service and repeated protected-key use | Never ship proof app in the product; cap cycles, enforce one process operation, keep result private, and remove the module before distribution | Installed product dependency graph must not contain `proof-app` | Accepted development-only residual |
| C7-11 | Medium | `available` cleanup and later proof-row cleanup use separate SQLite connections/resources | Cleanup error follows a successfully verified archive | Internal proof residue can remain while UI receives failure | Return failure when any cleanup fails; use exact IDs/names; let the next proof remain fail-closed rather than silently replacing conflicting state | Inject operation/bundle/file cleanup failures and inspect exact residue/retry | Exact internal cleanup tests pass; additional physical fault injection remains commit 8/open evidence |
| C7-12 | Medium | iOS device tooling cannot display backup exclusion or protection class for container entries | Reviewer relies only on code/host tests | Physical evidence may overstate platform attributes | State exactly what device inspection proves; retain code and platform tests; require independent reviewer/manual backup tooling if stronger proof is needed | Backup/restore inspection on the signed app or reviewed platform entitlement/tool output | Code/host evidence only; physical metadata inspection open |
| C7-13 | Low | Public profile table is added before cross-device API exists | A partial implementation persists unused public metadata | Dead state complicates review or later becomes inconsistent | Keep it public-only, singleton, migration-tested, and unused until reviewed ABI consumes it; remove if final ABI chooses another model | Schema inspection and no-secret regression | Accepted temporary implementation scaffold |

## Negative inspection

- The UDL and generated bindings contain no generic encrypt/decrypt, key
  export, plaintext bytes, manifest bytes, SQL, arbitrary path, caller nonce,
  or detailed cryptographic error oracle.
- Authored Rust/Swift/Kotlin source contains no logger, stdout/stderr formatter,
  panic macro, `fatalError`, TODO, or unimplemented branch. Generated/vendor
  code is reviewed through exact regeneration/checksums rather than this text
  scan.
- The iOS executable links the core statically. Android core `LOAD` segments
  use 16 KiB alignment. No second cryptographic provider was added; JNA is the
  generated Kotlin call runtime.
- SQLite stores identifiers, timestamps, lengths, digests, state, generated
  names, public bundles, and an opaque sealed blob only until `available`. It
  never stores a private key, archive key, opened attachment key, or plaintext.
- Successful device containers contain no source, transport ciphertext,
  receive temp, verified plaintext, archive partial, attachment key, or sealed
  blob. The retained archive is locally encrypted; the proof subsequently
  removes its own archive as disposable fixture state.

The open critical finding is a scope truth, not an invitation to weaken the
bridge. A safety approval for a specific semantic interface—or a design change
approved in the private package authority—is required before implementation can
continue across devices.
