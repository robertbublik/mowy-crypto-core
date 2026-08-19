# C7-01 semantic cross-device proof contract

Status: Implemented and accepted by the implementing-agent boundary review.
The fixture-only host and physical evidence in `evidence/commit-9.md` closes
C7-01 for implementation; this review is not independent assurance.

- Package: P2 sealed envelope foundation
- Governing boundary: D26 native profile, state, and bridge
- Finding: `reviews/commit-7-hostile-review.md` C7-01
- Prepared: 2026-08-19
- Implemented: 2026-08-19

## Required journey

The contract exists only to prove this sequence with fabricated identities and
the deterministic public attachment fixture:

1. device B initializes protected state and publishes its signed public bundle;
2. device A validates and pins that bundle, creates the fixture, encrypts it,
   signs/seals the manifest to B, and durably commits an outbox;
3. an untrusted host relay copies only the public transfer record and opaque
   ciphertext;
4. device B durably stages the still-unopened sealed blob and exact public
   routing/descriptor fields;
5. device B process-terminates and restarts;
6. B resumes by only the opaque receiver operation ID, reloads the staged state
   and pinned public sender bundle, opens/authenticates the blob, verifies and
   decrypts the ciphertext, archives and verifies the fixture, erases the
   sealed blob/transport state, and returns a public receipt; and
7. A deletes only the exact disposable sender operation and fixture files.

The reciprocal device direction is a test of the same contract, not another
product operation.

## Exposed semantic values

`MowyPublicBundle` contains only the fields D25 already declares public:
account, device, and agreement-key UUIDs as 32 lowercase hexadecimal
characters; identity and agreement public keys as 64 lowercase hexadecimal
characters; the exact validity bounds; and the 128-character signature.
Imported fields are fixed-length decoded, signature/curve validated, required
active at the supplied public time, and pinned before use.

`MowyDevelopmentTransfer` contains only public operation/context UUIDs, the
public recipient-key selector, the 816-character hexadecimal opaque sealed
blob, public plaintext/ciphertext lengths, and the public ciphertext SHA-256.
The sender ciphertext path is returned separately only after the outbox commit.
The receiver destination path is returned only after the unopened transfer is
durably staged. A sender path is never accepted by the receiver.

The callable operations are bounded:

- `publish_development_bundle`: initialize/load one protected device profile
  and return its signed public bundle;
- `prepare_development_transfer`: validate/pin B's public bundle, create and
  encrypt only the deterministic bounded fixture, seal to B, commit the sender
  outbox, and return the public/opaque transfer record and exact app-private
  ciphertext path; A's bundle is obtained separately through the publication
  operation;
- `stage_development_transfer`: validate/pin A's public bundle, verify all
  public encodings and the exact recipient selector, durably store the unopened
  transfer, and return only B's exact generated ciphertext destination path;
- `resume_development_transfer`: accept only the receiver operation UUID,
  reconstruct all other inputs from B's durable state after restart, then
  authenticate/decrypt/archive/verify/erase and return the existing public
  receipt; and
- `cleanup_development_sender`: verify the supplied operation/asset against the
  durable outbox, then remove only its exact sender row and generated source and
  ciphertext paths.

All functions return the existing stable coarse codes. Optional result records
are absent on failure. No function returns a general parser result.

## Explicitly absent

The contract exposes no private, attachment, or archive key; opened manifest;
plaintext buffer; caller key/nonce/randomness; arbitrary input/output path;
general encrypt/decrypt/seal/open operation; SQL; namespace reset; debug bypass;
JavaScript registration; secret-dependent error; or success before its durable
transition.

The fixed protected-store callback remains platform TCB plumbing. Its twelve
words never enter a semantic result and are cleared by Rust and platform code.

## Durable staging rule

Schema v3 adds one public/sealed `development_transfer_inbox` table. State 1
holds the exact unopened sealed blob plus public sender/context/descriptor
fields. Promotion to receiver `waiting_for_ciphertext` and the replay ledger is
one SQLite transaction; the inbox transitions to state 2 and drops its duplicate
sealed bytes. The normal receiver transition drops its own sealed blob when
`available` commits. Thus a crash cannot leave an authenticated receiver row
without its replay entry, and successful archive commit leaves no sealed copy.

State 2 retains only public identifiers and descriptors until the fixture
receipt is verified and exact proof cleanup removes it. This gives restart code
the sender account/device lookup needed to reload the pinned public identity
without accepting it again from the caller.

## Hostile review controls

| ID | Severity | Precondition | Impact | Required control and regression |
| --- | --- | --- | --- | --- |
| C7R-01 | Critical | The transfer record becomes a general crypto or byte-export API | Product callers gain a new secret-bearing capability | Keep records public/opaque and fixture-only; ABI scan rejects secret/plaintext/general operation names |
| C7R-02 | Critical | B opens before durable staging/restart | The required crash boundary is not proven | Stage unopened exact bytes in schema v3; a tampered sealed blob stages, survives repository reopen, and fails only on resume |
| C7R-03 | High | Caller substitutes sender identity or recipient selector | Misattribution or wrong-device delivery | Verify/pin sender bundle; sealed inner rebinds sender, recipient, key, conversation, asset, and public key; hostile variants fail |
| C7R-04 | High | Caller passes an arbitrary sender path to B | Core reads unrelated app/private data | Receiver accepts no path and derives one exact ciphertext destination from authenticated asset state |
| C7R-05 | High | Duplicate stage or resume diverges after a crash | Replay or inconsistent archive state | Exact duplicates are idempotent; conflicting operation/tuple reuse fails; resume handles staged, waiting, verified, and available states |
| C7R-06 | High | Inbox retains sealed material after archive commit | Erasure claim is false | Inbox drops sealed bytes on promotion; receiver drops its sealed blob on `available`; post-success SQL inspection proves neither remains |
| C7R-07 | Medium | Public strings are oversized, uppercase, malformed, or ambiguous | Parser/resource abuse or cross-platform disagreement | Exact lowercase hexadecimal lengths, non-nil UUIDs, canonical validity, fixed sealed length, and bounded fixture length are enforced before state mutation |
| C7R-08 | Medium | Stage returns a path before durable state exists | Relay creates an unowned ciphertext file | Commit and sync SQLite transaction first; only then derive/return the fixed destination; orphan cleanup is exact and idempotent |
| C7R-09 | Medium | Sender cleanup deletes another operation or asset | Local data loss | Require operation/outbox/asset match and fixed generated filenames; conflict otherwise |
| C7R-10 | Medium | Platform serialization is mistaken for a product wire format | Later code depends on proof-only JSON/text | UniFFI records are the boundary; proof-app relay files are versioned public test plumbing and explicitly non-product |

The implementation preserves these controls. The generated UDL exposes only
the five named operations and public/opaque records above; the two-store host
journey, hostile staged-tamper case, generated-binding drift check, signed
platform builds, and physical iPhone-to-Huawei relay/restart journey are
recorded in `evidence/commit-9.md`. Any later need for a raw key, opened
manifest, arbitrary path, new primitive, or product JavaScript surface returns
this contract to blocked rather than widening it.
