# Mowy crypto core

Status: Approved implementation boundary; cryptographic implementation has not
started.

This repository is the planned public, permissively licensed native
cryptographic core for Mowy Package P2. It will contain the byte-exact sealed
manifest, streaming attachment envelope, device-key operations, durable native
state, public disposable vectors, generated UniFFI bindings, and their tests.
The private application repository owns product UI, account and service
configuration, hosted delivery, and real user data.

The governing design is currently maintained in the private application
repository. Before implementation commit 1, this repository must be public and
the throwaway mobile feasibility spike must pass. Complete public format
documentation, vectors, dependency evidence, licences, notices, and exact
application revision linkage are P2 closeout requirements.

## Security boundary

The core is intended to keep private keys, attachment keys, archive keys,
opened manifests, and plaintext byte buffers behind a narrow native API. It is
not yet implemented or independently reviewed, and this repository currently
makes no confidentiality, interoperability, audit, or production-readiness
claim.

Even after P2 implementation, this core alone will not provide:

- account or device identity verification;
- product conversation authorization or ciphertext delivery;
- groups, multiple active devices, key escrow, or replacement-device recovery;
- forward secrecy beyond the approved rotating sealed-key model;
- post-compromise security, metadata hiding, or traffic-analysis resistance;
- permission to protect real recordings or make an end-to-end-encryption
  claim before independent review of the finished integration.

Only fabricated identities and disposable public fixtures belong here. Never
commit production identifiers, service configuration, credentials, private
keys, tokens, or meaningful recordings.

## Reporting vulnerabilities

Please follow [SECURITY.md](SECURITY.md). Do not disclose a suspected
vulnerability in a public issue.

## Licence

Apache License 2.0. See [LICENSE](LICENSE).
