# Commit 10 hostile review

Status: Implementing-agent security review of the controlled physical iOS
relock harness, semantic retry regression, evidence integrity, and claim
boundary. It is not an independent security assessment.

- Scope: protected-callback ordering, durable receiver state, plaintext and
  transport lifetimes, public error/receipt behavior, development-app
  isolation, locked-readable evidence, background execution, physical setup,
  cleanup, and claim strength
- Reviewed: 2026-08-20
- Prior findings: C7-04, C7-06, C7-11, C9-10, C9-11

## Findings

| ID | Classification / severity | Attack precondition and execution path | Impact and invariant | Evidence and smallest safe remediation | Regression / disposition |
| --- | --- | --- | --- | --- | --- |
| C10-01 | Evidence defect / Medium | `resume-relock-probe` receives an operation already in `available`; callback eight then occurs during available recovery rather than after fresh decryption and before promotion | The same coarse `UNAVAILABLE`/no-receipt verdict could be misreported as proof of the intended plaintext boundary; production confidentiality is unchanged | Restrict the mode to a newly staged, never-resumed operation; require prelaunch and locked inventories of source 0, ciphertext 1, receive-temp 0, verified 0, archive 0; require unlock success and byte-identical retry from the same operation | Source comment, platform instructions, deterministic fresh-stage test, and physical inventory enforce the claim. The coarse verdict alone is explicitly insufficient; resolved for this gate |
| C10-02 | Evidence defect / Medium | A prior `SUCCESS` verdict exists and a later receipt create, attribute, truncate, write, or sync fails, or an already-running app is relaunched without executing setup | Stale coarse evidence can be mistaken for the current physical run | Remove and recreate the exact receipt before starting core work; abort on preparation failure; remove it on write/sync failure; require process termination and observation of one fresh `LOCK_DEVICE_NOW` to final transition | Final wrapper fails closed on every handled receipt operation. Physical evidence already observed the live transition; future procedure requires the same. Resolved without adding an identifier to the receipt |
| C10-03 | Availability / Low | The user does not lock within 45 seconds, iOS refuses/expires the background task, or remaining background time falls below the safety margin | The app may suspend before a final verdict and retain retryable durable state; no plaintext may be reported or promoted merely because the harness timed out | Install an expiration handler, check remaining background time, and force the protected callback unavailable whenever the checkpoint cannot be safely observed | Final wrapper returns no success receipt on checkpoint-write failure, task denial/expiry, or timeout. Process termination may still omit a final verdict, which is a failed evidence run rather than a false pass; resolved |
| C10-04 | Test completeness / Low | Exact cleanup returns success but a later repository regression removes files without deleting the owned rows | The test name could overstate exact cleanup even though directory assertions pass | Reopen both repositories after cleanup and assert the sender outbox, transfer inbox, and receiver state are absent before checking all five directories | Added to `semantic_receiver_relock_retries_by_opaque_operation_and_cleans_exactly`; resolved |
| C10-05 | Proof-harness limitation / Medium | The discarded self-contained proof locks after creating a source and `encrypting` row; exact SQLite cleanup runs while the database has complete file protection | Cleanup can fail with `STORAGE`; a public bundle and/or disposable sender metadata row may remain even though no transport key, sealed blob, ciphertext, plaintext, archive, or receipt exists | Preserve cleanup-error precedence; do not relabel it unavailable. Use semantic resume for the physical gate. Add a durable exact-ID cleanup journal only if the self-contained mid-operation path ever becomes supported | Empty fixed file inventory is recorded, database cleanup is not claimed, and no broad database export/reset was performed. Accepted development-evidence limitation; it does not affect the passing semantic operation or product data |
| C10-06 | Defense in depth / Low | A local actor can read the proof app's private temporary directory while the iPhone is locked | The actor learns that a development probe reached a checkpoint and its coarse result | Keep only fixed mode/code/booleans, mode `0600`, no identifiers/paths/digests/lengths, and retain complete protection on every core artifact | Source and receipt inspection pass. Accepted development-only exception; no product target contains this file |
| C10-07 | Claim error / Low | A reviewer treats the temporary co-resident sender identity as another physical cross-device proof | Platform relock evidence could be inflated into an interoperability claim | State that the run proves physical iOS locking with two independent protected containers only; retain commit 9 as the sole iPhone-to-Huawei interoperability evidence | Public evidence and private handoff make the distinction explicit; resolved |
| C10-08 | False positive / Low | The Rust test adds availability scripting to `TestStore`, and the Swift proof app wraps `NativeProtectedKeyStore` | Reviewers may infer a changed production adapter, key policy, ABI, or cryptographic transition | Verify configuration boundaries and generated files | Rust changes are under `#[cfg(test)]`; Swift changes compile only in the proof-app target. UDL, generated bindings, production bridge/store, Keychain class, core transitions, and product repository are unchanged; no defect |

## Trace conclusions

For a newly staged receiver, the eighth Rust callback occurs after the full
ciphertext has authenticated, decrypted, synced, and been validated as a
regular file, and before the repository marks verified temp or the file is
promoted. When that callback reports unavailable,
`complete_waiting` removes the exact receive-temp file and returns unavailable.
The durable promoted transfer and normal waiting receiver retain the sealed
manifest only in the normal receiver row, retain the opaque ciphertext, and
can recover by the same operation ID. No receipt or path is returned.

The deterministic test covers that exact fresh path through the public façade.
It observes the durable rows and the file inventory at failure, then proves
unlock recovery, repeat idempotence, exact row deletion, and exact file
cleanup. The physical run adds real `UIApplication` protected-data state and a
manual passcode lock at the same checkpoint. Neither result proves arbitrary
callback timing or every platform version.

The locked-readable verdict is a consciously isolated evidence channel. Its
freshness and durability now fail closed: a new run deletes and recreates the
exact file before the worker starts; checkpoint/final writes truncate, write,
sync, and close; failure removes the file or aborts the run. Consumers must
still terminate the prior app process and observe the same run's checkpoint
transition rather than polling for the word `SUCCESS` alone.

The source build after these review remediations compiles and links for a
generic iOS device. The physical run preceded the receipt-freshness and
background-expiration hardening but already satisfied their evidence
preconditions through an observed fresh checkpoint-to-final sequence. Those
post-run changes affect only false-positive resistance in the proof harness;
the production core, callback position, physical lock, cleanup, retry, and
receipt result exercised on device are unchanged. A later independent reviewer
may request another signed manual run if their exact-binary policy includes
development evidence plumbing.

No open Critical or High finding was identified. C9-10 and the physical-iOS
portion of C7-04 are resolved as implementing-agent evidence. C9-11's hazardous
physical disk-full/rename/kill matrix, broader platform lifecycle coverage,
and independent human review remain open. This review authorizes no real
recording, product integration, P3, Milestone 3 entry, or encryption claim.
