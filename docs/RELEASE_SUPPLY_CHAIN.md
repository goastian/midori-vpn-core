# MidoriVPN 2.0 release supply-chain contract

This document defines the artifacts and evidence required before MidoriVPN
2.0.0 can be published. It does not authorize a push, tag, registry upload,
store submission or public release. Release preparation must happen from clean
trees whose exact commits are recorded; working branches are not release refs.

## Release set

All components use version `2.0.0` and derive from an annotated `v2.0.0` tag
created only after final approval. A release is incomplete unless every
applicable evidence file is produced from the same source revision.

| Component | Primary artifact | Required evidence | Signing authority |
|---|---|---|---|
| Core | `ghcr.io/goastian/midori-vpn-core:2.0.0` at an immutable digest | SPDX JSON SBOM, BuildKit provenance, GitHub build and SBOM attestations, SHA-256 digest | GitHub Actions OIDC keyless identity and Cosign |
| Control | `ghcr.io/goastian/midori-vpn-control:2.0.0` at an immutable digest | SPDX JSON SBOM, BuildKit provenance, GitHub build and SBOM attestations, SHA-256 digest | GitHub Actions OIDC keyless identity and Cosign |
| Linux Desktop | `midori-vpn-2.0.0-1.x86_64.rpm` | exported RPM public key, `SHA256SUMS`, SPDX JSON SBOM, build provenance and dependency report | existing OpenPGP Ed25519 release identity |
| Firefox/Midori | AMO upload ZIP, matching reviewer source ZIP and AMO-signed XPI | `SHA256SUMS`, SPDX JSON SBOM, exact public build inputs and reviewer build instructions | Mozilla Add-ons signing service |
| Chromium | Chrome Web Store upload ZIP and store-delivered package | `SHA256SUMS`, SPDX JSON SBOM, exact public build inputs and manifest validation | Chrome Web Store signing service |

The RPM trust anchor is the existing primary fingerprint
`BE000EFBCD8F4CDA53FC1A9F13FC1FEEE3315359`; the current signing subkey is
`84218F95A58E644EDB6947336CF4082EE316F221`. A release build must stop if that
secret identity is unavailable. It must never generate or silently substitute
a new key.

## Build and provenance rules

1. The version in the Git tag, package metadata, browser manifest and RPM spec
   must match exactly. The four repositories must be clean and their full
   commit hashes must be recorded in one release manifest.
2. Builders, scanners and workflow actions must be pinned to immutable image
   digests or full action commit SHAs. Mutable `latest`, release branches and
   floating major tags are not release inputs.
3. Build outputs are created in empty directories. `SOURCE_DATE_EPOCH` comes
   from the tagged commit. ZIP entries have sorted names, normalized modes and
   that timestamp; a second clean build must produce the same hash or record a
   specific, reviewed exception.
4. SPDX JSON is the interchange SBOM format for RPM, extension ZIPs and OCI
   images. The SBOM describes the final artifact, not only the source
   repository, and is itself hashed in `SHA256SUMS`.
5. Provenance binds the artifact SHA-256 or OCI digest to the repository,
   workflow, commit, tag, builder and declared public build inputs. GitHub
   artifact attestations complement but do not replace local hash and package
   signature verification.
6. Public extension endpoints and OAuth public-client identifiers are build
   inputs, not secrets. They must be recorded without placing AMO, CWS, GitHub
   or OpenPGP credentials in artifacts, logs or source archives.
7. OCI images are signed only by digest with short-lived GitHub Actions OIDC.
   Do not create a long-lived Cosign private key. Both signature and
   attestations must be verified against the exact repository workflow
   identity and `https://token.actions.githubusercontent.com` issuer.
8. External release jobs require a protected release environment and explicit
   operator approval. A build-only job must remain available without registry,
   GitHub Release, AMO or CWS write access.

## Browser-store packages

The Firefox manifest already declares the stable ID `midorivpn@astian.org`.
The AMO submission uses a browser-specific ZIP with `manifest.json` at its
root. Because the production code is bundled and minified, each submitted
version also needs a source archive made from tracked files, including
`package-lock.json`, a public build-input manifest and commands that reproduce
the submitted ZIP. `web-ext lint` must pass before any `web-ext sign` request.

The Chrome package is a separate ZIP built from the Chrome manifest. It must
not contain Firefox-only background scripts or `browser_specific_settings`.
The Chrome Web Store item/publisher identifiers and credentials are operator
inputs; they are not inferred or committed. Upload and publish are separate
operations so review can occur without automatically making a version public.

AMO JWT credentials and Chrome Web Store OAuth/service-account credentials are
stored only in a protected release environment. Local and pull-request builds
must not receive them.

## Required verification

Run these checks against final artifacts, replacing placeholders with the
approved tag, repository and immutable digest:

```bash
# Desktop: isolated RPM trust database and complete payload integrity.
rpm --dbpath /tmp/midorivpn-rpmdb --initdb
rpm --dbpath /tmp/midorivpn-rpmdb --import RPM-GPG-KEY-midorivpn
rpmkeys --dbpath /tmp/midorivpn-rpmdb --checksig --verbose \
  midori-vpn-2.0.0-1.x86_64.rpm
sha256sum --check SHA256SUMS

# GitHub build/SBOM attestations.
gh attestation verify oci://ghcr.io/goastian/midori-vpn-core@sha256:<digest> \
  --repo goastian/midori-vpn-core

# Public Sigstore signature. Keep the workflow identity exact.
cosign verify \
  --certificate-identity \
  'https://github.com/goastian/midori-vpn-core/.github/workflows/publish.yml@refs/tags/v2.0.0' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  ghcr.io/goastian/midori-vpn-core@sha256:<digest>
```

Equivalent attestation and Cosign verification is required for the Control
image with its own repository identity. Browser packages must pass both
browser-specific manifest checks, contain no Node `process` reference or
development CSP origin, and be installed only from the signed store result for
the permanent-install gate.

## Implementation status and remaining operator inputs

The source-side SIG-01 gaps are closed. Core and Control separate read-only
build evidence from protected publication, pin workflow dependencies, produce
SBOM/provenance and verify GitHub attestations plus keyless Cosign signatures by
digest. Desktop uses a pinned RPM builder, the established OpenPGP identity, an
isolated verification database, SPDX, provenance and checksums. The extension
produces separate deterministic browser packages, AMO reviewer source,
store metadata, SPDX, provenance and checksums, and validates Firefox with the
locked `web-ext` version.

The remaining release gates are deliberately external to source control:

- final approval and creation of the annotated `v2.0.0` tag;
- protected GitHub environments, reviewers and enable switches;
- the established RPM private identity in the protected signing environment;
- AMO credentials and Chrome Web Store publisher/item IDs, OAuth credentials,
  public privacy-policy URL and completed dashboard listing declarations;
- store-signed packages and post-signing installation verification.

None of those inputs may be inferred, committed or bypassed. No source-side
completion is evidence that an external artifact has been uploaded or
published.

## Build-only evidence gate

The first release stage is intentionally non-publishing. Core and Control
produce OCI archives with embedded BuildKit SBOM/provenance plus an independent
Syft SPDX document. Desktop verifies its existing OpenPGP identity in an
isolated RPM database before producing SPDX and local provenance. The extension
creates distinct, normalized Firefox and Chromium ZIPs, a reviewer source ZIP,
SPDX documents and local provenance. Every set carries `SHA256SUMS` and is kept
only as a short-lived CI artifact for human review.

These build jobs have read-only repository permissions and no registry login,
GitHub Release, store upload or public deployment step. Publication, GitHub
attestation and keyless OCI signing remain a separate approval-gated stage.

## Approval-gated signing stage

Core and Control provide a separate manual `publish.yml` bound to the annotated
`v2.0.0` tag and the protected `release-production` environment. Each refuses
to replace an existing version tag, pushes one immutable digest, creates GitHub
SLSA and SPDX attestations, signs with the short-lived workflow OIDC identity
through Cosign 3.1.2, and verifies all three records immediately. Desktop uses
the protected `release-signing` environment and rejects any OpenPGP identity
other than the established primary and signing-subkey fingerprints.

Environment configuration and the operator sequence are documented in
[`RELEASE_OPERATIONS.md`](RELEASE_OPERATIONS.md). Merely committing these
workflows does not authorize running them.

## External references

- [GitHub artifact attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations)
- [Sigstore container signing](https://docs.sigstore.dev/cosign/signing/signing_with_containers/)
- [Mozilla source-code submission](https://extensionworkshop.com/documentation/publish/source-code-submission/)
- [Mozilla `web-ext` signing](https://extensionworkshop.com/documentation/develop/web-ext-command-reference/)
- [Chrome extension preparation](https://developer.chrome.com/docs/webstore/prepare/)
- [Chrome Web Store API](https://developer.chrome.com/docs/webstore/using-api)
