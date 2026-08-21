# Commit 14 hostile review

Status: Implementing-agent hostile review of the rewritten-remote validation
checkpoint. Repository-controlled remediation passes. GitHub Support
submission/provider cleanup, the private-repository handoff, and independent
human review remain open. This is not independent security assurance.

- Scope: exact remote heads, fresh-clone independence, vendored completeness,
  history-category audit, validation warnings, pull-request state, provider
  ownership, recontamination, and completion wording
- Reviewed: 2026-08-20

## Findings

| ID | Classification / severity | Attack precondition and execution path | Impact and invariant | Evidence and smallest safe remediation | Regression / disposition |
| --- | --- | --- | --- | --- | --- |
| C14-01 | Wrong-ref validation / High | A local replacement commit is mistaken for the public branch or one of the three scoped branches is not updated | Reviewers inspect a different graph and the repository remains partly contaminated | Compare each scoped remote ref with its intended replacement and record the exact heads | **Resolved**: all three exact remote heads are recorded in commit-14 evidence |
| C14-02 | Dirty or inherited clone / High | Validation reuses the rewrite worktree or ignored local files | A passing gate can depend on objects or vendor files absent from Git | Clone from the rewritten remote, require a clean branch, and validate every vendored checksum entry | **Resolved**: fresh clone clean before this documentation; all 7,693 entries present and hash-correct |
| C14-03 | Identifier-audit underreach / High | Only the current tree or literal known strings are searched | Historical metadata or a transformed identifier remains reachable | Run the strict category/derived-token audit across every reachable blob and inspect commit email metadata | **Resolved**: zero matches across 6,928 blobs/16 commits; public no-reply metadata only |
| C14-04 | Gate-result inflation / Medium | Exit-zero cargo-deny output is generalized to refreshed non-yanked status or its fuzz-only licence allowance is treated as production use | Reviewers rely on assurance the local index did not provide | Preserve the exact yank-index and unmatched-NCSA warning boundaries | **Resolved wording**; optional trusted-index refresh remains later review input |
| C14-05 | Pull-request drift / High | A review link targets another head after remediation | Approval or comments attach to a revision other than the validated source | Verify PR #3's head and keep it draft while closeout gates remain | **Resolved at the validation baseline; final recheck pending**: PR #3 targeted the exact validated implementation head before this documentation-only commit and remained draft |
| C14-06 | Provider-cleanup overclaim / High | Branch deletion or force-update is called complete erasure | Read-only PR refs or cached object views can retain historical content | Submit the prepared Support request and record only what GitHub confirms | **Open external gate**: form prepared, not submitted pending maintainer confirmation |
| C14-07 | Support-request disclosure / Medium | The public evidence publishes superseded object coordinates needed only by Support | Public links make retained cached views easier to locate | Keep remediation coordinates inside the private Support submission | **Resolved in this evidence**: no superseded object ID is repeated |
| C14-08 | Old-clone recontamination / High | A pre-rewrite clone pushes or merges its graph into a cleaned branch | Removed objects become repository-reachable again | Replace or safely retire old durable clones and prohibit merges from pre-rewrite history | **Partially resolved**: the durable checkout was replaced from the rewritten remote; isolated task checkouts still require permanent retirement after the private remediation coordinates are recorded |
| C14-09 | Premature package status / High | Repository-controlled success is equated with final P2 completion | Provider cleanup and private handoff disappear from the review decision | Keep P2 at closeout candidate until Support submission/result and cross-repository inspection are recorded | **Resolved wording; completion remains pending** |
| C14-10 | Assurance-scope confusion / High | Final P2 status is read as independent approval for real recordings or product encryption | Unreviewed crypto/platform behavior reaches real user data | Preserve independent human review as the separate D27 gate and the P8 fault/compatibility carry-forward | **Open separate gate**; does not invalidate fixture-only validation |

## Hostile trace conclusion

The strongest repository-controlled failure modes from commit 13 are now
closed. The intended graph is visible at the three scoped public refs, the
draft PR pointed to the validated implementation head before this
documentation-only commit, and a clone made from that remote independently
proves the previously omitted vendored sources are present. The checksum-
manifest audit and complete exit-zero package gate do not depend on ignored
files from the rewrite worktree. The final PR head still requires the explicit
post-push inspection named above.

The history scan is broader than a search of current documentation: it checks
the derived sensitive categories across every reachable blob and constrains
reachable author/committer email metadata to the public no-reply identity. Its
zero result supports the rewritten branch graph. It cannot prove deletion from
unreachable provider storage, external clones, or cached views.

The remaining high-severity boundary is therefore operational and external,
not cryptographic source behavior. GitHub's
[official sensitive-data removal procedure](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository)
requires Support for eligible pull-request dereference and cached-view cleanup.
The request is prepared but not submitted. A prepared form is not a provider
action, and this review gives it no completion credit.

C14-06, C14-08, and C14-09 keep P2 at closeout candidate. Repository-controlled
remediation passes, but the package must not be marked Implemented until the
authorized Support step and private handoff are resolved and recorded.
Independent human review remains mandatory before real recordings or product
integration.
