# Commit 14 rewritten-remote validation evidence

Status: Repository-controlled public-history remediation and fresh-clone
validation are complete. GitHub Support submission and provider-owned
pull-request/cache cleanup are still pending, so P2 remains a closeout
candidate and is not marked Implemented, Verified, or production-ready.

- Package: P2 sealed envelope foundation
- Requirements: `M2-KEY-01`, `M2-ENVELOPE-01`, `M2-ASSURANCE-01`
- Validated public implementation head:
  `47d3e09a471a01a1f3bcc0edb01e60462eec4f85`
- Change class: remote-validation evidence and status documentation only
- Recorded: 2026-08-20

## Repository-controlled remediation result

The maintainer-authorized rewrite is now published on exactly the three
public-core branches in scope. Immediately before this documentation-only
commit was created, their verified remote heads were:

| Branch | Validated pre-documentation head |
| --- | --- |
| `main` | `ed99484ed9db3927904e4554005580f037b7135d` |
| `package/026-p2-sealed-envelope-foundation` | `079702bf71020c4c0464204ce3b0e06131a1b4a5` |
| `package/026-p2-sealed-envelope-foundation-implementation` | `47d3e09a471a01a1f3bcc0edb01e60462eec4f85` |

The validated implementation head was exposed for review by draft
[public-core PR #3](https://github.com/robertbublik/mowy-crypto-core/pull/3),
whose pre-documentation head was verified as
`47d3e09a471a01a1f3bcc0edb01e60462eec4f85`. This evidence commit changes only
documentation; its resulting PR head must be rechecked during the final private
handoff. The pull request is intentionally still draft while provider-owned
cleanup and cross-repository handoff remain open. No superseded object ID is
repeated in this evidence.

This result closes the branch-update and remote-head gates identified by
commit 13. It does not make GitHub's read-only pull-request refs or cached
object views repository-controlled. It also does not transfer an old commit
signature, check, approval, comment, or attestation to any replacement object.

## Fresh-clone validation

A new clone was made from the rewritten public remote rather than copied from
the history-rebuild checkout. The implementation branch was clean before the
commit-14 documentation was drafted.

The following checks passed against that clone:

- every one of the 7,693 files named by the vendored crate checksum manifests
  was present and matched its pinned hash;
- the strict category/derived-token history audit found zero matches across
  6,928 reachable blobs and all 16 rewritten commits;
- author and committer email metadata in the reachable history contained only
  the project's public GitHub no-reply identity; and
- `scripts/check.sh` completed with exit status zero.

The complete script result includes formatting, warning-denying clippy, all
83 Rust tests, fuzz-target compilation, all four frozen mobile release builds,
signed-libsodium and supply-chain checks, generated-binding drift checks,
Swift protected-store tests, Android unit tests and lint, the normalized SBOM
comparison, and the clean network-denied rebuild/test phase described in
commit-13 evidence.

The cargo-deny result retains the same explicit warning boundary. Its four
policy categories passed, but local registry-index lookup failures do not
establish refreshed current yank status for every locked crate. The unmatched
NCSA allowance remains expected for the separately checked fuzz dependency
graph and is not evidence that NCSA appears in the production graph. Neither
warning is silently upgraded into a stronger assurance claim.

## GitHub-owned cleanup boundary

The GitHub Support form required by GitHub's
[official sensitive-data removal procedure](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository)
has been prepared but **has not been submitted**. Submission is waiting for
the maintainer's confirmation. The prepared request identifies the
repository, the two affected historical public pull requests, the first
changed commit, and the absence of Git LFS. The superseded first-changed object
ID and any support-only details are deliberately not reproduced in public
evidence.

Until the request is submitted and GitHub reports the eligible dereference,
server-side garbage collection, and cached-view cleanup it performed, this
repository makes no universal-erasure claim. Independent clones and
provider-retained objects are outside the guarantee of a branch rewrite.

## Remaining closeout gates

The following work remains outside this commit's repository-controlled remote
validation:

1. obtain maintainer confirmation and submit the prepared GitHub Support
   request;
2. record GitHub's response and the exact provider-owned cleanup completed;
3. update the private application repository and PR #7 to the replacement
   public heads without rewriting its history; and
4. complete final cross-repository changed-file, link, status, and handoff
   inspection; and
5. permanently retire the isolated pre-rewrite and validation checkouts after
   every required private remediation coordinate has been recorded.

Independent human design and implementation review remains the separate D27
gate before real recordings, product integration, or an end-to-end-encryption
claim. The accepted personal-device safety disposition and later P8 platform
fault/compatibility work remain exactly as bounded in commit-13 evidence.

## Conclusion

The exact repository-controlled branch rewrite is published, reviewable, and
reproducible from a clean remote clone. The hosting-provider cleanup request is
prepared but not submitted, so this is a validated remediation checkpoint,
not final P2 completion and not proof that every historical object is erased.
