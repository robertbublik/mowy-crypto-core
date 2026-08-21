# Commit 4 hostile review

Status: Implemented agent review; not independent cryptographic assurance.

- Scope: 128-byte manifest parser, 296-byte signed region, Ed25519 sender
  verification, 360-byte inner lifetime, 408-byte sealed box, selector and
  recipient binding, identity/identifier checks, and public ABI
- Reviewed: 2026-08-19
- Reviewer: implementing agent in a separate hostile pass
- Independent-review status: open; this review cannot authorize real data

## Findings

| ID | Severity | Precondition | Execution path | Impact | Remediation | Required regression | Disposition |
| --- | --- | --- | --- | --- | --- | --- | --- |
| C4-01 | Critical | Successfully opened sealed-box plaintext first lands in an ordinary `Vec<u8>` | The fixed inner buffer is copied and an error returns before the vector allocation is cleared | The attachment key and signed manifest remain in freed process memory longer than intended | Wrap the libsodium output vector in `Zeroizing` immediately, copy only into a second zeroizing fixed array, and explicitly clear the array before return | Source inspection plus every open success/failure path and strict no-log scan | Resolved |
| C4-02 | High | A sender signs a manifest, and a recipient opens then re-seals the authentic inner plaintext to another device | Sealed-box confidentiality alone authenticates no intended recipient | A third device can mistake forwarded content for content addressed to it | Sign sender identity plus exact recipient device, key ID, and X25519 public key before sealing; compare all three to the selected local key after signature verification | Re-sealed forwarding attempt opens cryptographically but returns `RecipientMismatch` | Resolved |
| C4-03 | High | An attacker strips or replaces the detached signature and re-seals an otherwise readable inner value | Recipient accepts sealed-box integrity as sender authentication | Content can be misattributed | Require the trusted pinned Ed25519 key and verify the exact 296-byte signed region before any recipient or manifest acceptance | Zeroed/replaced signature re-sealed to the correct recipient returns `Signature` | Resolved |
| C4-04 | High | An attacker supplies the correct public key ID with a different private key, an unknown selector, or an expired selector | Selection trusts routing metadata or trial-decrypts multiple retained secrets | Oracle behavior, stale-key acceptance, or wrong-key processing | Require one preselected local key, constant-time selector equality, exact active window, and one sealed-box open; never scan | Wrong secret with same selector, wrong selector, and exact expiry boundary regressions | Resolved in core; protected lookup remains commit 7 |
| C4-05 | High | Outer signed conversation/asset values differ from the embedded manifest or from operation context | Decryption later reconstructs associated data from a different identifier source | Cross-conversation or cross-asset confusion | Verify the sender signature first, parse the canonical manifest, then compare outer, embedded, and expected identifiers with fixed-size libsodium comparison | Validly re-signed disagreement and caller-context mismatch both return `IdentifierMismatch` | Resolved |
| C4-06 | Medium | A local retained-key record carries a malformed duration or overflowed time window | An active-time comparison alone accepts a noncanonical key record | Key lifetime policy diverges across code paths | Reconstruct and validate the exact 30-day window when the protected secret is loaded | Malformed window constructor rejection plus exact expiry test | Resolved |
| C4-07 | High | A blob is short, long, random, or altered | The wrapper allocates from attacker length or parser reads a partial inner value | Memory abuse, parser panic, downgrade, or partial acceptance | Require exactly 408 bytes at parse, obtain exactly 360 bytes after open, use fixed arrays, and accept no alternate version/algorithm/trailing bytes | Length fuzz, exact-size random fuzz, ciphertext tamper, and signed unknown-version regressions | Resolved |
| C4-08 | High | The attachment manifest is cloned, debug-formatted, logged, or returned through a public façade | Secret-bearing bytes outlive the operation or cross JavaScript | Attachment-key disclosure | Store all 128 bytes in a non-cloneable zeroizing owner, expose only internal narrow accessors, add no `Debug`/display implementation, and leave UDL unchanged | Generated ABI drift and negative source inspection | Resolved |
| C4-09 | Medium | A reviewer assumes successful open already records replay or durable receiver state | This slice has no operation/replay transaction by design | Duplicate or conflicting delivery can be accepted if integration proceeds early | Keep the module internal and block bridge exposure until commit 5 adds replay and durable state | Commit-5 transaction/replay regressions and unchanged UDL now | Accepted slice boundary; blocks integration claim |
| C4-10 | Low | A deterministic test expects exact sealed-box bytes | Libsodium correctly generates a fresh ephemeral sealed-box key | A brittle vector could pressure production randomness toward determinism | Freeze the exact signed inner bytes by public hashes/signature and prove two seals differ while both open | Public inner vector and repeated-seal inequality | Resolved |

## Negative inspection

- No attachment key, opened manifest, private agreement key, private identity
  key, plaintext, caller randomness, or general seal/open primitive enters the
  UDL, generated bindings, logs, errors, evidence, or SQLite.
- The only returned delivery bytes are one fixed 408-byte sealed ciphertext and
  a public canonical key selector. The 360-byte opened plaintext cannot be
  constructed through the public crate boundary.
- Authored code has no `unwrap`, `expect`, `panic`, `todo`, `unimplemented`,
  `dbg`, stdout, or stderr path. Structural fuzz/property cases return errors.
- Identity, X25519 public key, and UUID bindings use libsodium fixed-size
  comparison; fixed magic/version/length structure uses ordinary checks only.
- Sealed-box failure details and libsodium/provider strings are discarded in
  favor of stable bounded error variants.

C4-04 and C4-09 retain their named integration work. Independent review of the
completed implementation remains mandatory before real recordings.
