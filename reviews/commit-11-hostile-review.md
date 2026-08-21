# Commit 11 hostile review

Status: Implementing-agent privacy and supply-chain review of the public
evidence redaction and local-only iOS signing configuration. It is not an
independent security assessment.

- Scope: project-owned evidence, proof-app Xcode settings, signed-build
  reproducibility, generated SBOM provenance, Git-history limits, and claim
  accuracy
- Reviewed: 2026-08-20

## Findings

| ID | Classification / severity | Attack precondition and execution path | Impact and invariant | Evidence and smallest safe remediation | Regression / disposition |
| --- | --- | --- | --- | --- | --- |
| C11-01 | Privacy/evidence boundary / High | A reader inspects already-published evidence commits or cached Git objects containing local device/signing identifiers | Local device and developer-account metadata is unnecessarily public; the rule that durable evidence contains normalized results only is violated | Remove the values from the current tree; do not repeat them in review output; obtain explicit maintainer authority before coordinated history/cache remediation | Current tree remediated and category-only scan required. Historical copies remain open external remediation; this append-only commit does not claim erasure |
| C11-02 | Build reproducibility / Medium | Removing a committed development team makes a signed physical build run without an explicit local override | The signed proof can fail at provisioning, or an operator can be tempted to recommit a personal value | Keep generic builds unsigned; require the team only through local Xcode state or task-specific command-line override; document the boundary | Proof project contains no team assignment and platform guidance names the local override. Full deterministic/generic-device gates must pass |
| C11-03 | Audit false positive / Low | A broad scanner treats public artifact SHA-256 values, device model names, or generated upstream SBOM author metadata as signing identifiers | Useful reproducibility/provenance evidence could be removed without improving privacy | Classify fields by provenance and redact only local device/signing values | Artifact hashes, model/OS results, and upstream SBOM metadata retained intentionally |

## Conclusion

No production code or cryptographic invariant changes. The current tree can be
reviewed and built without a committed personal signing-team value, but the
already-published history limitation remains open. A history rewrite, force
update, cache-removal request, or downstream notification is outside this
append-only correction and requires explicit maintainer authorization.

## Subsequent commit-13 review note

That authorization was later granted for a strictly bounded public-core
rewrite, and a replacement history is now prepared locally. The original
C11-01 conclusion remains historically accurate: branch-tip redaction alone
did not erase published objects. Commit 13 separately records the replacement
map and limits the repository-controlled operation to the public core's
`main`, package-foundation, and implementation branches.

Public-core PR #1 and closed draft PR #2 are the affected pull requests.
GitHub owns their internal references and cached views, so their dereference is
a Support operation after the three branches are updated; it is not evidence
that can be manufactured by a local or branch force-push. Private application
PR #7 is not rewritten and needs only replacement-hash links. The inventory
found no forks, releases, Actions artifacts, or Actions caches, but it cannot
exclude independent clones or GitHub object caches.

All rewritten commit identifiers are new. Any old commit/tag signature or
attestation is invalid for a replacement object, and old checks, approvals,
comments, or links must not be presented as validation of the new history.
Final status remains pending the force-updates, GitHub Support action,
fresh-clone/category validation, and exact remote evidence.
