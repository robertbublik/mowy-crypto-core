# Commit 8 hostile review

Status: Implementing-agent assurance review; incomplete where named and not an
independent security assessment.

- Scope: fuzz harness fidelity, corpus handling, sanitizer/toolchain behavior,
  physical memory evidence, dependency inventory, negative inspection, and
  evidence-claim strength
- Reviewed: 2026-08-19

## Findings

| ID | Severity | Precondition | Execution path | Impact | Remediation | Required regression | Disposition |
| --- | --- | --- | --- | --- | --- | --- | --- |
| C8-01 | Critical | A sanitizer-free fuzz run is presented as satisfying sanitizer-capable host testing | Apple ASan link fails; `--sanitizer none` runs pass | Memory-unsafe behavior in native dependencies could remain undetected while evidence overclaims | Label coverage-only result exactly; rerun identical locks/source/corpora under compatible Linux ASan or obtain reviewed tooling resolution | Both targets complete a bounded ASan run with no artifact; exact compiler/container recorded | **Open assurance item** |
| C8-02 | High | Fuzz support copies or simplifies parser logic | Harness diverges from production source while reporting parser coverage | Findings and non-findings do not apply to shipped code | Compile production module files in place in an rlib-only package; keep helper limited to fixture construction/input adaptation | Stable `cfg(fuzzing)` compile plus review of path attributes; normal artifact has no fuzz symbol/API | Resolved |
| C8-03 | High | Random sealed bytes never authenticate | Outer crypto rejects every input before inner parser/signature/identifier branches | Fuzzer provides almost no coverage of load-bearing signed-inner parser | Start from exact public-vector signed inner and apply structured offset/XOR mutations after production fixture construction | Empty `mutate:` seed reaches valid inner; mutations cover domain/identity/signature/recipient/manifest paths | Resolved for parser coverage; sealed-box implementation itself remains dependency-owned |
| C8-04 | High | Envelope digest rejects mutation before record authentication | Fuzzer mutates ciphertext but manifest retains stale digest | Secretstream parser, tags, final/trailing checks are rarely reached | Recompute public digest/geometry in the harness, then call the production two-pass verifier/decryptor with fixed disposable binding/key | Exact public vector reaches valid path; mutation can pass framing/digest and fail authentication safely | Resolved |
| C8-05 | High | LibFuzzer mutates the supplied corpus directory in place | Source corpus is passed directly | Nondeterministic binary files pollute commits and obscure seed provenance | Copy four auditable text seeds to unique temp directories and remove on exit | `scripts/check-fuzz.sh` leaves `git status` and source corpus unchanged | Resolved after one caught run; generated mutations were removed before commit |
| C8-06 | High | Minimal-manifest `cargo vendor` targets the established vendor directory | Cargo mirrors only the minimal graph and removes unrelated packages | Millions of tracked source lines disappear or an incomplete supply-chain snapshot is committed | Restore exact tracked vendor state; retain only three new crates; document safe future sync procedure | Git diff shows no tracked vendor modification and exactly three new package directories | Resolved before commit |
| C8-07 | Medium | Fuzz dependencies are absent from the production SBOM | Fuzz graph is a separate unpublished package | Reviewer misses tool/runtime licences or checksums | Commit a separate exact fuzz lock; document role, checksums, licences, and exclusion from shipped SBOM; run cargo-deny on that manifest | Advisories/bans/licences/sources all report ok | Resolved with offline index warnings disclosed |
| C8-08 | Medium | One-time JNA/native allocation is counted as per-cycle retention or excluded without disclosure | Baseline placement changes after a failed memory run | Memory evidence can be biased either way | Preserve failing cold-baseline result; use exactly one maximum warmup and disclose measurement APIs/bounds | Ten measured cycles on each device plus force-stop/terminate relaunch | Resolved for settled memory claim |
| C8-09 | Medium | Device receipt/container/log inspection captures unrelated private device data | Broad shell/container/log commands are used | Public evidence leaks installed apps, user data, or secrets | Retain only exact app-private public receipt and fixed namespace metadata; do not retain broad dumps or full containers | Evidence documents only scoped values; no raw log/container archive committed | Resolved after one broad diagnostic was consciously excluded |
| C8-10 | Medium | Absence of proof-app log calls is generalized to absence of all platform logging | OS/Gradle/Xcode/native runtimes emit their own diagnostics | Review understates metadata exposure or noise | Claim only authored-source negative inspection; attach no crash reporter; independently review runtime diagnostics for real integration | Static authored-source scan and filtered proof process review | Partially resolved; real product logging remains later integration work |
| C8-11 | Medium | Physical success is taken as a complete fault matrix | Only relaunch, Android locked launch, and deterministic host fault injection are covered | Disk-full, kill timing, and iOS relock regressions can survive | Execute named physical kill/disk/rename/iOS-lock cases or keep them explicit for independent review | Durable matrix with exact result per transition/device | Open |
| C8-12 | Low | Fuzz nightly is confused with the production compiler pin | Temporary toolchain is installed to run cargo-fuzz | Review believes mobile code moved from stable 1.97.1 | Keep nightly under `/private/tmp`, document exact purpose/version, and continue building every normal/mobile artifact with stable 1.97.1 | Full stable gate plus fuzz-only nightly command | Resolved |

## Conclusion

The fuzz design now reaches meaningful valid and hostile parser states without
widening the production ABI, and the two bounded coverage-guided runs are
reproducible from committed text seeds and vendored inputs. The review does not
convert missing ASan, physical fault cases, the cross-device proof, or
independent human review into passes. Those limitations must stay visible in
both repository PRs and the private package handoff.
