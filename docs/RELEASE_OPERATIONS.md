# MidoriVPN 2.0 release operations

This runbook prepares the approved signing path. It does not authorize running
the signing workflows, creating a tag, pushing an image or publishing a
release. Local working branches must never be used as release refs.

## Required protected environments

Before any release attempt, repository administrators create these GitHub
environments and enable required reviewers, prevent self-review where the plan
supports it, and restrict deployment refs to the annotated `v2.0.0` tag:

| Repository | Environment | Required variable or secret |
|---|---|---|
| Core | `release-production` | variable `RELEASE_SIGNING_ENABLED=true` |
| Control | `release-production` | variable `RELEASE_SIGNING_ENABLED=true` |
| Desktop | `release-signing` | variable `RELEASE_SIGNING_ENABLED=true`; secret `RPM_SIGNING_PRIVATE_KEY` |

The environment switch is deliberately absent by default. Do not create the
RPM secret from a new identity. It must import the established primary
fingerprint `BE000EFBCD8F4CDA53FC1A9F13FC1FEEE3315359` and signing subkey
`84218F95A58E644EDB6947336CF4082EE316F221`.

Acceptable recovery paths are the original encrypted offline backup or the
original hardware token. Import or attach it only in an operator-controlled
GnuPG home or the protected GitHub environment. Never place private key
material in the repository, an artifact, a command argument or a log. The
Desktop repository's
[`scripts/check-rpm-signing-identity.sh`](https://github.com/goastian/midori-vpn-desktop/blob/main/scripts/check-rpm-signing-identity.sh)
must pass before rebuilding.

## OCI publication gate

Core and Control each expose a separate `publish.yml`. The workflow:

1. Runs only through manual dispatch from the annotated `v2.0.0` tag.
2. Requires the exact confirmation `publish-v2.0.0` before requesting the
   protected `release-production` environment.
3. Refuses to overwrite an existing `2.0.0` registry tag.
4. Builds and pushes one `linux/amd64` image, then addresses it only by digest.
5. Produces BuildKit provenance/SBOM and an independent Syft SPDX document.
6. Creates GitHub provenance and SBOM attestations for that digest.
7. Signs that digest with the short-lived GitHub Actions OIDC identity using
   Cosign 3.1.2; no persistent Cosign key exists.
8. Immediately verifies the exact workflow identity, OIDC issuer and both
   attestation predicate types.

The workflow file, Actions and scanner are pinned to full commits or image
digests. It has `packages`, `id-token`, `attestations` and artifact metadata
write access only inside the protected publication job.

## Desktop signing gate

Desktop signing runs manually from the annotated `v2.0.0` tag, requires the
exact confirmation `sign-v2.0.0`, a full Core license commit and approval of
the `release-signing` environment. The imported key is checked against both
established fingerprints before the rootless RPM builder starts. The result is
retained privately for review; this job does not create a GitHub Release or
publish a package repository.

After obtaining an approved RPM, verify from its artifact directory:

```bash
sha256sum --check SHA256SUMS
rpm --dbpath /tmp/midorivpn-rpmdb --initdb
rpm --dbpath /tmp/midorivpn-rpmdb --import RPM-GPG-KEY-midorivpn
rpmkeys --dbpath /tmp/midorivpn-rpmdb --checksig --verbose \
  midori-vpn-2.0.0-1.x86_64.rpm
```

## Independent OCI verification

Use the immutable digest printed by the approved workflow, never a tag:

```bash
bash scripts/release/verify-oci-release.sh core \
  sha256:<approved-core-digest>
bash scripts/release/verify-oci-release.sh control \
  sha256:<approved-control-digest>
```

The verifier requires Cosign 3.1.2 and a current GitHub CLI. It checks the
exact `publish.yml@refs/tags/v2.0.0` certificate identity, GitHub's OIDC issuer,
SLSA provenance and SPDX 2.3 SBOM attestations.

Stop the release if an expected environment, reviewer, fingerprint, annotated
tag, digest, signature or attestation is absent. Never repair a failed gate by
weakening it or replacing the established signing identity.
