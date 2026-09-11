# MidoriVPN 2.0 release operations

This runbook prepares the approved signing path. It does not authorize running
the signing workflows, creating a tag, pushing an image or publishing a
release. Local working branches must never be used as release refs.

For host preparation, installation, upgrade, rollback, recovery, rotation,
observability and the 2.0.0 availability boundary, continue with
[`PRODUCTION_DEPLOYMENT.md`](PRODUCTION_DEPLOYMENT.md).

## Required Actions credentials and production environment

The private repositories create candidate artifacts only. Their repository
credentials do not authorize production. The public production repository owns
the only GitHub Environment approval gate supported by the current GitHub Free
topology:

| Repository | Scope | Required variable or secret |
|---|---|---|
| Private Core `midori-vpn-core-dev` | repository Actions | variables `MIDORIVPN_PRIVATE_CANDIDATE_ENABLED=true` and `MIDORIVPN_RELEASE_READ_USER`; `MIDORIVPN_RELEASE_SOURCE_TOKEN` is a fine-grained PAT limited to read-only Contents on the other three private repositories; separate `MIDORIVPN_RELEASE_READ_TOKEN` has only classic `read:packages` for private GHCR |
| Private Control `midori-vpn-control-dev` | repository Actions | variable `MIDORIVPN_PRIVATE_CANDIDATE_ENABLED=true` |
| Public production Core `midori-vpn-core` | `deploy-production` | protected deployment variables/secrets below; required reviewers; only protected `v*` tags |
| Desktop | operator-controlled local signing | established OpenPGP identity; never copy `RPM_SIGNING_PRIVATE_KEY` into an unprotected repository Secret |

On GitHub Free, private repository Variables and Secrets are available but
private Environments, deployment branches and tag rulesets are not. A private
tag therefore starts candidate publication without a GitHub approval prompt.
Limit write access, review all four exact commits and tags out of band, and
treat the resulting private images as non-production until the protected public
tag and `deploy-production` approval both pass.
`MIDORIVPN_PRIVATE_CANDIDATE_ENABLED` is a fail-closed switch, not an approval
control.

The private candidate switch is deliberately absent by default. Any future
protected RPM secret must import the established primary
fingerprint `BE000EFBCD8F4CDA53FC1A9F13FC1FEEE3315359` and signing subkey
`84218F95A58E644EDB6947336CF4082EE316F221`.

Acceptable recovery paths are the original encrypted offline backup or the
original hardware token. Import or attach it only in an operator-controlled
GnuPG home. A private `release-signing` Environment may be used only after
moving to a GitHub plan that supports the required protection; a repository
Secret is not an acceptable substitute. Never place private key
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

GitHub Free cannot protect `v*` in private repositories. Only the authorized
release operator may create the same annotated tag locally at each reviewed
frozen commit. Push Control, Desktop and Extension first, wait for the private
Control candidate to pass, and push Core last. The Core tag is the coordinator:
it checks out all four tags, rejects a lightweight, missing or mismatched tag
and emits the
authoritative schema-3 source manifest with separate product version, release
version and Git tag. Product metadata stays `2.0.0`; `v2.0.0-rc.1` remains the
failed Control reproducibility attempt and the next coordinated candidate is
release `2.0.0-rc.2` under `v2.0.0-rc.2`. Never repair failure by moving a
tag; use a new version.

After private candidate publication is complete, promote the exact frozen Core
commit to the public production repository. Its enforced `v*` tag ruleset must
forbid deletion and force-update and restrict creation to release operators.
Creating the matching annotated public tag is a separate authorized action; it
starts only `deploy.yml`. The public controller retrieves the successful
private Core workflow artifact, requires its Core commit to equal the public
tag commit and never rebuilds or re-signs either image.

## Private OCI candidate publication

Control and Core `publish.yml` run only from pushed semantic tags in their
private `*-dev` repositories. Each validates its repository-level enable
switch, refuses an existing version, builds cleanly twice, requires equal
digests and pushes a third identical build. All three use the same
`SOURCE_DATE_EPOCH` and `rewrite-timestamp=true` exporter contract and
explicitly disable BuildKit's default/embedded attestations so execution-
specific manifests or unnormalized layer timestamps do not contaminate the
digest comparison. The workflow then scans the exact digest and uses Cosign
3.1.3 keyless OIDC to sign it and attach independently generated SLSA v1
provenance plus SPDX attestations as private OCI referrers. It immediately
verifies all three records against the exact tag-bound workflow identity.
GitHub creates a new package as private; the job queries
the package after publication and fails unless its effective visibility is
exactly `private`. The GitHub Packages REST API has no visibility-update
endpoint, so the workflow does not attempt an unsupported mutation.
The pinned Syft container receives the job's temporary Docker credential file
through a read-only `/auth/config.json` mount and `DOCKER_CONFIG=/auth`; this is
required for direct digest scans of private GHCR images.

The non-publishing build-evidence workflows scan their OCI archives by
extracting each one to a private temporary layout, validating `oci-layout` and
`index.json`, and mounting that directory read-only into the pinned Trivy
container. Temporary layouts are removed on success and failure.

Core waits up to twenty minutes for the same-version Control digest and verifies
its private visibility, Control workflow certificate identity and both
attestations before publishing Core. It then creates a deterministic bundle
containing host scripts/templates, public operator documentation, four commits,
two OCI digests, database schema compatibility and checksums. It contains no
deployment values, pull token, SSH key or application secret.

Both read-only credentials must be available as repository- or
organization-level Actions secrets because Core validates tags before any
production gate. `MIDORIVPN_RELEASE_SOURCE_TOKEN` must be a fine-grained PAT
limited to the Control, Desktop and Extension private repositories with
read-only Contents access. `MIDORIVPN_RELEASE_READ_TOKEN` must remain a
separate classic PAT with only `read:packages`; the workflow pairs it with
`MIDORIVPN_RELEASE_READ_USER` for the Control pull and private visibility
check. Attestation bundles are read from the authenticated OCI registry, so
the source token needs no Attestations permission. The workflow logs in again
with the job-scoped `GITHUB_TOKEN` before publishing Core.

The bundle stores the exact pull tags and their expected digests separately.
The workflow file, Actions and scanner are pinned to full commits or image
digests. Candidate jobs use only `packages: write`, `id-token: write` and
`contents: read`; they do not request GitHub artifact-attestation permissions,
which are unavailable for private repositories on the current organization
plan. Neither workflow
creates a GitHub Release or changes package visibility to public.

## Protected deployment environment

The public production Core `deploy-production` Environment is a second
independent approval gate. Its tag must identify the same frozen Core commit as
the private bundle; the controller downloads rather than rebuilds that bundle.
Configure these non-secret Variables:

- `MIDORIVPN_DEPLOY_ENABLED=true`
- `MIDORIVPN_DEPLOY_HOST`, `MIDORIVPN_DEPLOY_PORT`, `MIDORIVPN_DEPLOY_USER`,
  `MIDORIVPN_DEPLOY_SERVICE_USER`
- `MIDORIVPN_GHCR_PULL_USER`
- `MIDORIVPN_DEPLOY_VALUES`, a newline-delimited dotenv fragment containing
  only keys classified as `variable`

Configure these Secrets:

- `MIDORIVPN_DEPLOY_SSH_PRIVATE_KEY`
- `MIDORIVPN_DEPLOY_SSH_KNOWN_HOSTS`
- `MIDORIVPN_GHCR_PULL_TOKEN`, scoped only to read the two private packages
- `MIDORIVPN_PRIVATE_RELEASE_TOKEN`, scoped to read the private Core workflow
  artifact; OCI attestations are read with the separate GHCR pull credential
- `MIDORIVPN_DEPLOY_SECRETS`, a newline-delimited dotenv fragment containing
  only keys classified as `secret`

[`deploy/ci/environment-map.json`](../deploy/ci/environment-map.json) is the
versioned classification authority. Its validator requires every host-managed
key exactly once. `CORE_IMAGE` and `CONTROL_IMAGE` cannot come from either
fragment; the workflow injects the verified complete version tags. Fragments patch
only their corresponding keys atomically and never replace the server `.env`.

Before SSH, the protected controller pulls every runtime tag and creates a
mode-0600 image lock containing the resolved digests. It verifies Core and
Control labels, exact private workflow identities, SLSA provenance and SPDX
attestations by those digests. SSH uses the supplied host key with strict
checking. The pull credential enters Podman through standard input. The host
pulls the tags again and rejects any digest change before installing Quadlets.
On an existing principal, deployment first
creates a custom-format PostgreSQL backup and proves an isolated restore. It
then renders and installs Quadlets, runs migration units, applies Nginx and
firewall configuration and requires the strict public 204 edge probe. Failure
restores application units, `.env`, Nginx and rules added by that attempt; it
retains the database backup and never restores production data automatically.

## Desktop signing gate

On the current GitHub Free plan, Desktop signing runs locally from the
annotated `v2.0.0` tag in an operator-controlled GnuPG home. It requires the
exact Core license commit and checks both established fingerprints before the
rootless RPM builder starts. The checked-in `release-signing` workflow is a
fail-closed optional path for a future plan with protected private
Environments; do not populate its key as a repository Secret. Neither path
creates a GitHub Release or publishes a package repository implicitly.

After obtaining an approved RPM, verify from its artifact directory:

```bash
sha256sum --check SHA256SUMS
rpm --dbpath /tmp/midorivpn-rpmdb --initdb
rpm --dbpath /tmp/midorivpn-rpmdb --import RPM-GPG-KEY-midorivpn
rpmkeys --dbpath /tmp/midorivpn-rpmdb --checksig --verbose \
  midori-vpn-2.0.0-1.x86_64.rpm
```

## Independent OCI verification

Use the release metadata and coordinated manifest. The verifier downloads by
the approved tag, requires its resolved digest to match `release.json`, then
checks the immutable verification reference:

```bash
bash scripts/release/verify-oci-release.sh core \
  release.json workspace-manifest.json
bash scripts/release/verify-oci-release.sh control \
  release.json workspace-manifest.json
```

The verifier requires Cosign 3.1.3. It checks the
exact private `publish.yml@refs/tags/<git_tag>` certificate identity, GitHub's
OIDC issuer, coordinated commit/version labels, SLSA provenance and SPDX 2.3
SBOM attestations.

Stop production if the public Environment, reviewer, public tag ruleset,
fingerprint, annotated tag, digest, signature or attestation is absent. Never
repair a failed gate by weakening it or replacing the established signing
identity.
