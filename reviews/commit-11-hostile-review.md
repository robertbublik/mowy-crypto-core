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
