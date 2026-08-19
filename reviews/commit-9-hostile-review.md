# Commit 9 hostile review

Status: Implementing-agent security review of the bounded semantic transfer,
durable staging, physical relay evidence, and sanitizer closeout. It is not an
independent security assessment.

- Scope: public/opaque ABI, validation and pinning, staged/relaunch state,
  replay/idempotence, paths, cleanup ordering, generated bindings, proof-app
  serialization, physical evidence handling, and claim strength
- Reviewed: 2026-08-19
- Governing contract: `reviews/c7-01-semantic-contract.md`

## Findings

| ID | Classification / severity | Attack precondition and execution path | Impact and invariant | Evidence and smallest safe remediation | Regression / disposition |
| --- | --- | --- | --- | --- | --- |
| C9-01 | Confirmed defect / Critical (resolved during implementation) | The first transfer-facing design exposes raw bytes, keys, opened manifests, caller paths, or a general encrypt/decrypt surface; product code can then repurpose a proof API | Secret exposure or a new unaudited protocol boundary; violates native-only secret ownership and the accepted C7 contract | Replace it with five fixture-only semantic operations and public/opaque records; no general byte/path/key operation in UDL or generated bindings | ABI scan, invalid-record tests, generated-binding drift; resolved |
| C9-02 | Confirmed defect / Critical (resolved during implementation) | Receiver stage calls open/authenticate before a durable unopened commit or accepts all inputs again after restart | The required crash boundary is fictional and attacker-controlled identity/context can change between stage and resume | Add strict schema-v3 inbox, store exact sealed bytes first, resume by operation ID only, pin sender bundle, and promote receiver plus replay atomically | Two-store relaunch test and hostile staged-tamper test; physical force-stop before first resume; resolved |
| C9-03 | Confirmed defect / High (resolved during implementation) | Receiver accepts a sender/relay-supplied local path | Confused deputy can read or overwrite unrelated app-private data; violates fixed namespace ownership | Accept no receiver path; derive one canonical ciphertext destination from the validated asset under the fixed root and return it only after stage commit | Hostile ABI/input tests and UDL inspection; resolved |
| C9-04 | Confirmed defect / High (resolved during implementation) | An exact duplicate stage is retried with a later wall-clock value and equality includes generated receive/expiry timestamps | Benign delivery retry conflicts, encouraging reset or duplicate state | Compare the caller-controlled transfer tuple and existing state, not newly derived timestamps; preserve the first durable receive/expiry values | Exact duplicate at later time is idempotent; conflicting tuple fails; resolved |
| C9-05 | Confirmed defect / High (resolved during implementation) | Sender cleanup deletes its database authorization row before generated files, then file deletion fails | Ciphertext/source becomes unowned and exact cleanup cannot be retried | Verify complete durable transfer, delete fixed generated files first, then delete the row; database failure leaves retry authorization | Failure ordering inspection and exact cleanup integration test; resolved |
| C9-06 | Confirmed defect / High (resolved in code) | Inbox or receiver row keeps a sealed copy after successful archive commit | Transport key remains recoverable and erasure claim is false | Clear inbox sealed bytes during atomic promotion and receiver sealed bytes on `available`; retain only public descriptors | SQL transition/rollback/sealed-null tests pass. Physical database export was intentionally not performed; code defect resolved, physical SQL inspection unavailable |
| C9-07 | Defense-in-depth / Medium | A later integrator treats proof-app `|` text as a product wire format | Ambiguous compatibility and accidental exposure of development plumbing | Document UniFFI records as the only ABI, keep text app-private and development-only, and add no parser to product/service code | Platform/core README and source comments; accepted limitation of the proof runner |
| C9-08 | Confirmed operational defect / Medium (resolved in procedure) | ADB receives unescaped `|` fields or reuses an already-running activity that only reads creation-time extras | Proof step does not reach the app or stale receipt is mistaken for new evidence | Quote the entire remote command, force-stop between modes, and require each receipt's explicit mode | Failed shell attempt and stale `publish` receipt retained in evidence; corrected stage/restart passed |
| C9-09 | Defense-in-depth / Medium | Evidence collection exports a full private database/container or copies a ciphertext merely to prove absence | Public review artifact may retain sealed material, identifiers, or unrelated device data | Reject broad copies; use fixed on-device file metadata, exact public receipts, and SQL tests against production repository code | Full DB and negative ciphertext copy were rejected; metadata-only inventories passed |
| C9-10 | Unproven assumption / Medium | Device locks during a live iOS prepare/resume transition | Key access may fail at a different point than host callbacks model; availability/retry behavior lacks physical timing evidence | Run a controlled signed-app mid-operation relock with no real data, or retain it as an explicit external review input without weakening Keychain class or checks | Open; iOS `WhenUnlockedThisDeviceOnly` storage and repeated protected-data checks are implemented, but physical timing is unobserved |
| C9-11 | Unproven assumption / Medium | Real device storage fills or a hostile local actor races exact rename/promotion boundaries | Platform-specific filesystem behavior may differ from deterministic fault adapters | Do not fill or corrupt personal devices merely for closeout; execute in disposable-device/emulator review infrastructure or accept exact host fault matrix explicitly | Open external assurance input; deterministic disk-full/rename/kill boundary tests pass |
| C9-12 | False positive / Low | The semantic ABI returns a ciphertext path, so it appears to accept arbitrary files | Caller might be assumed able to redirect core file access | Returned path is generated only beneath the validated fixed proof root after durable ownership; receiver accepts no path and sender cleanup recomputes fixed names | Source trace, canonical-path tests, symlink/regular-file checks; no caller path capability |

## Trace conclusions

Authorization for this development proof is deliberately narrower than product
authorization. Bundle signatures and pinning bind the two disposable device
profiles and sealed inner data binds sender, recipient key, conversation,
asset, descriptor, and attachment key. There is still no authenticated account
or human verification; that is a P3 requirement and is not hidden by calling
the fixture encrypted.

Every attacker-controlled string crosses exact lowercase-hex length and UUID
validation before state mutation. Public bundles are signature/curve/validity
checked and pinned. Stage rejects the local device as sender and the wrong
recipient selector. Resume reconstructs sender, context, sealed bytes, lengths,
digest, and paths from durable state rather than trusting the caller again.
Envelope authentication, exact length/digest/end-of-file checks, replay
ledger, archive verification, and terminal erasure remain the existing
production-source path.

The physical journey closes C7-01 for implementing-agent evidence: two devices
exchange only public/opaque values, the receiver stages before open, a process
restart occurs, resume needs only an opaque handle, the maximum fixture is
verified and archived, retry is stable, and exact sender/transport files are
gone. Linux ASan closes the previous sanitizer execution gap for the two
bounded fuzz targets.

No open confirmed vulnerability was found in this review. C9-10 and C9-11 are
honest unproven physical-platform assumptions, not converted to passes. The
review does not authorize real recordings, claim E2EE, replace P3 identity
binding, or satisfy the independent human review gate.
