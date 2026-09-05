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
| Core | `release-production` | variable `RELEASE_SIGNING_ENABLED=true`; `GITHUB_TOKEN` may read the private Control package |
| Control | `release-production` | variable `RELEASE_SIGNING_ENABLED=true` |
| Core | `deploy-production` | protected deployment variables/secrets below; required reviewers; only protected `v*` tags |
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

## Workspace manifest preflight

Before creating the approved tags, generate the four-repository source
manifest from a clean coordinated checkout. The repositories may be nested
under Core or cloned beside it, but all four must use the same branch state,
declare version 2.0.0 and have no uncommitted changes:

```bash
bash scripts/release/create-workspace-manifest.sh
```

The output records canonical component names and full commits. Review it before
tagging; `ALLOW_DIRTY_RELEASE_BUILD=true` is only for local diagnostics and is
not an acceptable release input.

Protect `v*` with repository rulesets in all four repositories: only release
operators may create it, deletion and force-update are forbidden, and the tag
must be annotated. Create the same tag locally at each frozen commit, then push
Control, Desktop and Extension first. Approve Control's `release-production`
job and push Core last. The Core tag is the coordinator: it checks out all four
tags, rejects a lightweight, missing or mismatched tag and emits the
authoritative schema-2 source manifest. Never repair failure by moving a tag;
use a new version.

## OCI publication gate

Control and Core `publish.yml` run only from pushed semantic tags. Each enters
the protected `release-production` environment, refuses an existing version,
builds cleanly twice, requires equal digests, pushes a third identical build,
scans the exact digest, creates independent SPDX plus GitHub provenance/SBOM
attestations and signs with Cosign 3.1.3 keyless OIDC. The job explicitly sets
and re-reads GHCR package visibility as `private`.

Core waits up to twenty minutes for the same-version Control digest and verifies
its private visibility, Control workflow certificate identity and both
attestations before publishing Core. It then creates a deterministic bundle
containing only host scripts/templates, four commits, two OCI digests, database
schema compatibility and checksums. It contains no deployment values, pull
token, SSH key or application secret.

The workflow file, Actions and scanner are pinned to full commits or image
digests. It has `packages`, `id-token`, `attestations` and artifact metadata
write access only inside the protected publication job. Neither workflow
creates a GitHub Release or changes package visibility to public.

## Protected deployment environment

The Core `deploy-production` Environment is a second independent approval gate.
Configure these non-secret Variables:

- `MIDORIVPN_DEPLOY_ENABLED=true`
- `MIDORIVPN_DEPLOY_HOST`, `MIDORIVPN_DEPLOY_PORT`, `MIDORIVPN_DEPLOY_USER`
- `MIDORIVPN_GHCR_PULL_USER`
- `MIDORIVPN_DEPLOY_VALUES`, a newline-delimited dotenv fragment containing
  only keys classified as `variable`

Configure these Secrets:

- `MIDORIVPN_DEPLOY_SSH_PRIVATE_KEY`
- `MIDORIVPN_DEPLOY_SSH_KNOWN_HOSTS`
- `MIDORIVPN_GHCR_PULL_TOKEN`, scoped only to read the two private packages
- `MIDORIVPN_DEPLOY_SECRETS`, a newline-delimited dotenv fragment containing
  only keys classified as `secret`

[`deploy/ci/environment-map.json`](../deploy/ci/environment-map.json) is the
versioned classification authority. Its validator requires every host-managed
key exactly once. `CORE_IMAGE` and `CONTROL_IMAGE` cannot come from either
fragment; the workflow injects the verified immutable digests. Fragments patch
only their corresponding keys atomically and never replace the server `.env`.

SSH uses the supplied host key with strict checking. The pull credential enters
Podman through standard input. On an existing principal, deployment first
creates a custom-format PostgreSQL backup and proves an isolated restore. It
then renders and installs Quadlets, runs migration units, applies Nginx and
firewall configuration and requires the strict public 204 edge probe. Failure
restores application units, `.env`, Nginx and rules added by that attempt; it
retains the database backup and never restores production data automatically.

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

The verifier requires Cosign 3.1.3 and a current GitHub CLI. It checks the
exact `publish.yml@refs/tags/v2.0.0` certificate identity, GitHub's OIDC issuer,
SLSA provenance and SPDX 2.3 SBOM attestations.

Stop the release if an expected environment, reviewer, fingerprint, annotated
tag, digest, signature or attestation is absent. Never repair a failed gate by
weakening it or replacing the established signing identity.
