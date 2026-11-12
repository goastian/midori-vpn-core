# MidoriVPN 2.0.0 production deployment

This is the operator entry point for installing and upgrading MidoriVPN 2.0.0.
It joins the release workflow, private registry, host automation, recovery and
availability contracts into one runbook. Detailed component behavior remains
in the linked specialist documents.

Preparing or committing this runbook does not authorize a tag, package upload,
deployment or external release. Every publication and deployment approval is a
separate operator decision.

## Supported topology and availability boundary

MidoriVPN 2.0.0 has one central authority and one or more data-plane nodes:

| Profile | Runs on the host | Receives central secrets |
| --- | --- | --- |
| `principal` | Control, PostgreSQL 18, PgBouncer, Redis, one Core, Prometheus and Grafana | Yes; it is the only profile with database, OIDC, Control signing and data-encryption secrets |
| `core-node` | Regional Core and its private replay Redis | No; it receives public trust, a one-use enrollment token and node-local credentials only |

The principal is a single point of control in 2.0.0. Control and PostgreSQL do
not have automatic failover, leader election or a synchronous replica. A
regional never promotes itself to Control and never accepts management from
another regional.

An established tunnel can continue on its current Core while the principal is
unavailable. New login, candidate discovery, session creation, policy change,
placement and durable cleanup depend on the principal and fail closed during
that outage. Client Core failover is therefore reconnection between eligible
Cores, not Control or PostgreSQL high availability. It requires a valid
candidate response from Control before the outage and healthy HTTPS edge probes;
it cannot manufacture a new authorized session without the principal.

The first production principal starts with an empty database. Moving a staging
database into production is not the default deployment path and requires a
separate, reviewed data-migration procedure. A first regional remains inactive
until the acceptance gate in
[`deploy/DEPLOYMENT_PROFILES.md`](../deploy/DEPLOYMENT_PROFILES.md) passes.

## Runtime and privilege model

Production uses systemd Quadlet on openSUSE. Hosts never compile the
application, follow `latest`, use registry auto-update or install a `.build`
unit. Every runtime image is a complete
`registry/path:major.minor.patch[-prerelease]` reference. CI resolves and records
the corresponding digest for verification, evidence and rollback, but hosts pull
and run the approved version tag.

Use the lowest working privilege level:

1. PostgreSQL, PgBouncer, Redis, Core, Control, Prometheus and Grafana run in
   rootless Podman under the dedicated `midorivpn` account.
2. WireGuard and MASQUE remain in the rootless Core pod. Firewalld maps the
   non-privileged MASQUE host port to public UDP/443.
3. OpenVPN/DCO and strongSwan/XFRM use optional rootful Quadlets with host
   networking, a read-only filesystem and only the required network
   capabilities and PKI mounts.
4. Nginx, Certbot and firewalld remain host services because they own global
   ingress, certificates and firewall state.
5. A hardened host gateway is a recorded fallback only after the equivalent
   rootful gateway has failed its kernel data-plane test.

The pod infra container uses the exact `registry.k8s.io/pause:3.10.1` version
tag. Its resolved digest is captured in the protected runtime image lock before
deployment. That image supplies only the pod namespace process; this
deployment does not install, configure or operate Kubernetes.

PostgreSQL, PgBouncer, Redis, plain Core HTTP, Control container HTTP and
metrics must never be public. Nginx is the public TCP/TLS boundary. Grafana and
Prometheus bind only to loopback; regional TCP/9443 is restricted to the
private management path from the principal.

All principal-to-regional management uses the dedicated host interface
`mvpn-mgmt` (`10.254.240.1/32` to `10.254.240.2/32`). Enrollment, heartbeat,
desired state, Core peer operations and Prometheus traffic must not use the
regional's public hostname. TLS on private TCP/8443 uses the offline management
CA and remains verified; observability keeps its independent client-authenticated
TLS policy on TCP/9443. The customer WireGuard endpoint uses an unrelated
DNS-only 128-bit random label and UDP port. That opaque name reduces automated
noise but is not an authentication or confidentiality control.

### WireGuard namespace isolation

Core installs mandatory, interface-scoped INPUT and FORWARD chains before
bringing WireGuard up, including restoration and restart of an existing
interface. The `MVPN-IN-<interface>` and `MVPN-FW-<interface>` chains and tagged
jumps are MidoriVPN-owned. Filter updates are one `iptables-restore --noflush`
transaction; unrelated rules and base policies are preserved, and managed
protection is placed before historical permissive rules.

Rootless Core cannot load host kernel modules. Provision the approved host's
netfilter backend and its TCP/UDP, comment and conntrack extensions before
activation. Missing kernel support is a failed deployment gate, not permission
to ignore `iptables-restore` errors or revert to unrestricted forwarding.

VPN peers cannot access namespace-local services. TCP/UDP DNS is allowed only
to the pool gateway when that exact IP is configured in `VPN_DNS`. Peer-to-peer
forwarding, including mesh, is blocked in this MVP. Internet egress and its
established replies remain allowed. Failure to install protection aborts
startup and attempts to bring the interface down; a failure to disable it is
reported as well and requires immediate operator intervention. A NAT warning
never counts as evidence of working internet egress.

The kernel integration test is opt-in and must run in a disposable Podman
container with `NET_ADMIN` and `--network=none`, never in the host namespace.
It checks real backend parsing and idempotent rule reconciliation, not tunnel
traffic. Before accepting any deployment, connect real clients and verify
internet/DNS, isolation from other clients and refusal of PostgreSQL,
PgBouncer, Redis, Core HTTP and observability from the VPN interface.

## Release and deployment flow

The immutable release flow is:

```text
four clean commits
  -> same annotated semantic tag in all four private development repositories
  -> automatic private Control candidate publication
  -> Core verifies Control and the four-commit manifest
  -> automatic private Core candidate publication
  -> signatures, attestations, SBOM and vulnerability gates
  -> checksum-closed secret-free deployment bundle with operator documentation
  -> protected matching annotated tag on the public production Core
  -> independent protected public-repository deployment approval
  -> one approved destination host
```

The workflow deploys exactly one destination configured in the protected
`deploy-production` Environment per approved execution. It is not a fleet
orchestrator. Deploying another host uses a separately reviewed invocation of
the same verified bundle and runtime image lock; it must not move or recreate
the tag. Never change a protected destination while an approval is pending.

The source and release contracts are:

- [`docs/RELEASE_OPERATIONS.md`](RELEASE_OPERATIONS.md): private candidate
  credentials, the protected public Environment, coordinated tags and
  independent artifact verification;
- [`docs/RELEASE_SUPPLY_CHAIN.md`](RELEASE_SUPPLY_CHAIN.md): required artifacts,
  identities, SBOM and provenance;
- [`deploy/host/README.md`](../deploy/host/README.md): individual host commands;
- [`deploy/POSTGRESQL.md`](../deploy/POSTGRESQL.md): database roles, backup and
  explicit restore;
- [`deploy/OBSERVABILITY.md`](../deploy/OBSERVABILITY.md): private metrics and
  certificate rotation.

## Configure Actions credentials and the public production gate

GitHub Free does not provide protected Environments or tag rulesets for private
repositories. Core and Control private tags therefore generate private,
immutable candidates only. Configure these repository Variables:

```text
MIDORIVPN_PRIVATE_CANDIDATE_ENABLED=true
MIDORIVPN_RELEASE_READ_USER=<read-only GitHub identity>
```

The workflow-provided `GITHUB_TOKEN` performs each repository's own registry
and attestation operations. Control needs only
`MIDORIVPN_PRIVATE_CANDIDATE_ENABLED`. Core additionally requires two separate
repository- or organization-level Actions secrets:

- `MIDORIVPN_RELEASE_SOURCE_TOKEN`: a fine-grained PAT limited to the private
  Control, Desktop and Extension repositories with read-only Contents access.
- `MIDORIVPN_RELEASE_READ_TOKEN`: a classic PAT limited to `read:packages`,
  paired with `MIDORIVPN_RELEASE_READ_USER` to pull and inspect the private
  Control package.

Do not combine these privileges in one token and do not grant `repo` to the
package token. Attestation bundles are verified from the already authenticated
OCI registry. Do not create a long-lived Cosign private key: OCI signatures use
the short-lived GitHub Actions OIDC workflow identity. The Core workflow then
authenticates the Core push separately with its job `GITHUB_TOKEN`.

Repository Variables and Secrets are execution inputs, not a human approval
gate. Restrict private repository write access and review the exact four-commit
manifest before the authorized operator creates any candidate tags. A private
candidate is never permission to deploy.

### Deployment Environment

Create `deploy-production` in the public production Core repository. This is
the protected controller required by the GitHub Free topology. Store these
values as Environment Variables:

| Variable | Meaning |
| --- | --- |
| `MIDORIVPN_DEPLOY_ENABLED` | Explicit gate; must equal `true` |
| `MIDORIVPN_DEPLOY_HOST` | Exact approved DNS name, never a shell fragment |
| `MIDORIVPN_DEPLOY_PORT` | SSH port from 1 through 65535 |
| `MIDORIVPN_DEPLOY_USER` | Unprivileged SSH operator with the approved `sudo` path |
| `MIDORIVPN_DEPLOY_SERVICE_USER` | Dedicated non-root account that owns the rootless runtime, such as `midori` |
| `MIDORIVPN_GHCR_PULL_USER` | Identity with read-only access to the two private packages |
| `MIDORIVPN_DEPLOY_VALUES` | Multiline dotenv fragment containing non-secret managed values |

Store these values as Environment Secrets:

| Secret | Meaning |
| --- | --- |
| `MIDORIVPN_DEPLOY_SSH_PRIVATE_KEY` | Dedicated deployment key |
| `MIDORIVPN_DEPLOY_SSH_KNOWN_HOSTS` | Out-of-band verified host-key line for the exact host and port |
| `MIDORIVPN_GHCR_PULL_TOKEN` | Read-only package token, passed to Podman through standard input |
| `MIDORIVPN_PRIVATE_RELEASE_TOKEN` | Read-only access to the private Core release workflow artifact and attestations |
| `MIDORIVPN_DEPLOY_SECRETS` | Multiline dotenv fragment containing secret managed values |

Create an enforced public tag ruleset for `v*`: restrict tag creation to the
release operators and reject updates and deletion. Restrict
`deploy-production` to that tag pattern, require an explicit reviewer and
prevent self-review when a second authorized reviewer is available. The
Environment and ruleset are the production authorization; the private
candidate tags are not.

Do not put application secrets in repository secrets shared with unrelated
workflows. Do not put the SSH key, host inventory or registry token in either
dotenv fragment.

## Build the two configuration fragments

[`deploy/ci/environment-map.json`](../deploy/ci/environment-map.json) is the
classification authority. It classifies every host-managed key exactly once as
`variable` or `secret`. The validator rejects unknown, duplicated and
misclassified keys. `CORE_IMAGE` and `CONTROL_IMAGE` are reserved even though
they appear in the host allowlist: the workflow injects their verified exact
version tags and rejects either key in an Actions fragment. Digests travel in
the separate generated runtime image lock, never as `.env` values.

Use `.env.example` to determine the keys required by the selected profile, and
query the map instead of guessing a classification:

```bash
jq -r '.managed_env | to_entries[] | select(.value == "variable") | .key' \
  deploy/ci/environment-map.json
jq -r '.managed_env | to_entries[] | select(.value == "secret") | .key' \
  deploy/ci/environment-map.json

bash scripts/release/validate-deployment-environment-map.sh
```

Each fragment uses one `KEY=value` entry per line. It is a patch, not a
replacement `.env`. `DEPLOYMENT_PROFILE` must always be present in the variable
fragment so composition cannot cross the principal/regional boundary. On the
first installation the fragments must contain every value required to render
that profile. On an upgrade they may repeat the approved managed configuration,
but unmanaged server-local lines, comments and ordering remain untouched. Empty
values are meaningful only where `.env.example` explicitly permits them.

A principal variable fragment begins with profile and routing data such as:

```dotenv
DEPLOYMENT_PROFILE=principal
CORE_NODE_NAME=principal-1
APP_ENV=production
DOMAIN=vpn.example.com
PUBLIC_BASE_URL=https://vpn.example.com
ALLOW_LEGACY_HMAC_TRANSPORT_TOKENS=false
```

The secret fragment contains only the secret-classified keys needed by that
profile, for example database role passwords, `REDIS_PASSWORD`, the Authentik
client secret when used, the Control Ed25519 private key and
`CONTROL_DATA_ENCRYPTION_KEY`. Paths to private key files belong in the
variable fragment; the private file contents do not.

A regional fragment sets `DEPLOYMENT_PROFILE=core-node` and must leave all
Control, PostgreSQL, Authentik, client-CA signing and data-encryption secrets
empty. The renderer fails closed if any forbidden central value reaches a
regional. Install the one-use enrollment token as a regular mode-0600 file in
the mode-0700 node state directory, not in GitHub Variables or the deployment
bundle.

The host patcher:

- accepts only keys in `deploy/host/managed-env-keys.txt`;
- writes a private temporary file and atomically renames it;
- preserves all unmanaged content;
- records a mode-0600 backup when an environment already exists; and
- never writes secret values to command arguments or normal output.

### Authentication and device quota checks

Access tokens must have an `aud` containing `AUTHENTIK_CLIENT_ID`. A matching
issuer or `azp` alone is not sufficient. The same audience requirement applies
to HTTP, WebSocket and introspected tokens, including cached results. Public
PKCE clients should use asymmetrically signed access tokens verifiable through
JWKS; opaque/encrypted tokens still require server-side introspection
credentials. Never embed a client secret in Desktop or the extension.

Before rollout, validate a real token from each supported client and confirm
that a token from another application of the same issuer returns 401. Local
synthetic-token tests are not certification of the production Authentik setup.

When `ASTIAN_PAYMENT_URL` is empty, billing and its entitlement cache are not
consulted: `MAX_DEVICES_PER_USER` determines the concurrent-device quota. Zero
uses the existing default of five; it does not mean unlimited. With billing
configured, the current subscription limit remains authoritative. Provider
outage policy is a separate billing acceptance task, not changed by the
free-beta fallback correction.

## Coordinate and publish the release

1. Freeze clean, reviewed commits for Core, Control, Desktop and Extension.
2. Run `bash scripts/release/create-workspace-manifest.sh` from the coordinated
   checkout and review the four full commit IDs and version.
3. Create the same annotated semantic tag in all four private `*-dev`
   repositories. Product metadata remains `2.0.0`; inventory existing refs
   before choosing a fresh, explicitly authorized candidate version. Existing
   candidate tags must never be moved or reused. A lightweight tag is invalid.
   Check the dated acceptance gates in [PROJECT_STATUS.md](PROJECT_STATUS.md).
4. Push Control, Desktop and Extension first. Wait for the private Control
   candidate and all non-publishing evidence jobs to pass.
5. Push Core last. Core is the candidate coordinator and rejects missing, moved or
   mismatched tags and commits.
6. Review both private package visibilities, three matching build digests,
   vulnerability reports, SPDX documents, provenance and Cosign verification.
7. Promote the frozen Core commit to the public production repository and,
   only under separate authorization, create the matching annotated tag there
   through the enforced public `v*` ruleset.
8. Review the generated bundle checksum and `release.json` before approving a
   deployment. The public controller downloads that exact private workflow
   artifact; it never rebuilds the images.

Never repair a failed immutable release by moving or deleting its tag. Correct
the source and use a new version. Neither workflow creates a public GitHub
Release or changes a GHCR package to public.

## Prepare a host

The normal Actions deployment performs these steps after approval. The commands
below are for preflight, audited manual recovery or diagnosing a failed gate;
they do not bypass the protected workflow.

Required host conditions:

- supported x86_64 openSUSE with working systemd user sessions;
- DNS and TLS names already approved;
- an unprivileged SSH operator with the exact reviewed `sudo` path;
- enough persistent storage for PostgreSQL, application state, observability
  state, deployment snapshots and database backups;
- outbound access to GHCR and required identity providers;
- public TCP/80 and TCP/443 as approved, plus only the enabled VPN transport
  ports; and
- a private principal-to-regional management route when a regional is used.

Inspect and then apply host preparation:

```bash
sudo bash deploy/host/prepare-opensuse.sh --check --service-user midorivpn
sudo bash deploy/host/prepare-opensuse.sh --apply --service-user midorivpn
```

This creates the dedicated service account and private directories, installs
the required Podman/Nginx/firewalld/SELinux packages and enables user linger.
It preserves an existing Certbot installation when the Nginx plugin works;
otherwise it installs the native Leap or Tumbleweed package names. It also
requires Podman Quadlet and subordinate UID/GID ranges of at least 65,536 IDs.
The protected `MIDORIVPN_DEPLOY_SERVICE_USER` value must match the account used
here and cannot be `root`. The preparer does not issue a certificate, open
firewall ports or build an image.

Use an out-of-band channel to verify the SSH host fingerprint before storing
`MIDORIVPN_DEPLOY_SSH_KNOWN_HOSTS`. Do not obtain trust with `ssh-keyscan` in the
same unauthenticated job that will deploy.

## Install a principal

Before approval:

1. Generate and separately escrow `CONTROL_DATA_ENCRYPTION_KEY`, the Control
   Ed25519 identity, database credentials and CA material. Never put an escrow
   copy in the deployment artifact.
2. Provision Authentik redirect origins and exact CORS/trusted-proxy values.
3. Provision server and observability certificates with the required DNS and
   URI SANs. Private key files are mode 0600.
4. Keep OpenVPN and IKEv2 disabled until their authenticated client E2E gates
   have passed.
5. Confirm every non-application runtime image also uses an approved exact
   version tag and that its resolved digest matches the release evidence.

Approve the `deploy-production` job only after checking the destination and
fragments. The workflow then:

1. verifies and expands the secret-free bundle;
2. composes an allowlisted mode-0600 patch with the verified Core and Control
   version tags;
3. pulls every runtime tag on the protected runner, records its digest, and
   verifies Core/Control labels, Cosign identities, provenance and SPDX
   attestations;
4. establishes strict SSH trust and logs in to GHCR through standard input;
5. prepares the host and copies the release plus image lock into the service
   user's private
   release directory;
6. creates and proves an isolated restore of the current database when one
   exists;
7. patches the existing environment atomically;
8. pulls every tag again as the service user and refuses installation if any
   resolved digest differs from the protected lock;
9. renders and checksum-verifies rootless and optional rootful Quadlets;
10. runs the database role policy and one-shot migration before Core;
11. applies exact Nginx and firewalld configuration; and
12. requires local readiness plus the public edge-health contract.

The raw composed patch exists only while the environment is being updated and
is removed on success or handled failure. The rendered staging tree is also
removed after installation; the active private environment files and explicit
rollback snapshots remain protected under the service account.

The edge URL must return exactly HTTP 204 with an empty body and
`Cache-Control: no-store`. HTTP 200 or HTML means Nginx reached the SPA fallback
and blocks rollout. After this route passes, configure the corresponding
server's authenticated `probe_url` to the same exact HTTPS URL. Host automation
does not guess or mutate a historical server row.

A new principal may temporarily start without its modeled node identity only
to create the initial cluster, node and one-use enrollment token through the
administrator API. It is ineligible for placement in that state. Install all
node identity settings together and restart immediately; partial settings fail
startup.

### First modeled Core activation (MVP-CORE-01)

After the empty database has been migrated and role policy applied, use the
administrator API to create the inventory, not ad-hoc bootstrap inserts:

1. `POST /api/v1/admin/clusters` creates the inactive cluster.
2. `POST /api/v1/admin/clusters/{clusterID}/nodes` creates the enrolling node.
3. Issue its one-use token with
   `POST /api/v1/admin/nodes/{nodeID}/enrollment-token`, install the node identity
   settings and complete enrollment. Enrollment leaves the node **inactive**.
4. Publish signed intent with `POST /api/v1/admin/nodes/{nodeID}/desired-state`.
   Wait for a healthy, compatible heartbeat reporting that latest revision and
   a still-valid desired lease. Do not insert an observation or extend a lease
   manually to manufacture eligibility.
5. `POST /api/v1/admin/servers` creates the unbound server with explicit
   transport inventory and its verified HTTPS `probe_url`. Wait for central
   transport health to be fresh and healthy; certificate transports additionally
   require centrally recorded certification from their real acceptance gate.

Review the three returned UUIDs and select the protocol that must be eligible.
Under the principal's dedicated rootless service account, load the existing
protected migrator credentials into the environment without printing them or
putting passwords on a command line. Then run:

```bash
export POSTGRES_CONTAINER=midori-postgres
export POSTGRES_DB=midori_vpn
export POSTGRES_MIGRATOR_USER=midori_migrator
# POSTGRES_MIGRATOR_PASSWORD is injected from the protected operator environment.
bash scripts/activate-core.sh "$CLUSTER_ID" "$NODE_ID" "$SERVER_ID" wireguard
```

This operator-only command uses `psql` **inside the existing PostgreSQL
container**, directly over private loopback TCP/5432 with the migrator identity;
it needs no host Go/PostgreSQL runtime, extra image, published database port or
regional database credentials. It does not use PgBouncer. The runtime role is
not accepted: the session must be the configured migrator and have schema
creation privilege under the existing database policy. This check is a guard
against operator mistakes, not a new privilege boundary against a compromised
runtime role that already has table DML permissions.

`deploy/postgres/activate-core.sql` locks the inventory and performs cluster
activation, node activation and server binding in **one serializable
transaction**. Before commit it calls the existing
`vpn_server_placement_eligible(server, protocol, '90 seconds', TRUE)` gate with
the legacy exception disabled. It does not change transport health,
certification, capacity, desired state, node identity or the server's active
flag. Failure, including failure of that final gate, rolls back every write.

The command refuses draining/revoked/retired authority, unenrolled nodes,
inactive/draining servers, inconsistent observations, legacy-exempt servers,
cross-cluster identity, occupied nodes and **every cross-node reassignment**.
An initial binding also refuses existing peers, valid device certificates,
live operations or nonzero server/node peer counts. Activating an inactive
cluster is refused if that would also enable another already-active node.
Use the separate reviewed lifecycle procedure for those cases; do not clear a
drain, session, binding or legacy flag merely to make this command pass.

A repeat with the same inventory and still-eligible state succeeds without
changing timestamps. A later unhealthy/full/expired state is not excused by a
previous success: the repeat fails closed and leaves existing state unchanged.
Concurrent execution can return a serialization or bounded lock error; inspect
inventory and retry the whole command, never just one of its updates. A lost
connection after commit can likewise be resolved by rerunning the command.
Record the successful UUID/protocol output with the operator's private gate
evidence. Failure has a nonzero exit status and no partial activation. After a
successful commit, use the normal administrative drain/revoke workflow if
activation must be withdrawn; there is no automatic unbind or SQL rollback of
an already accepted node.

The PostgreSQL integration suite creates cluster/node/server inventory through
the real admin handlers, exercises enrollment and signed desired-state
issuance, checks the production SQL transaction and asserts idempotency,
concurrency and failure atomicity. Run against an isolated migrated test
database with schema-capable test credentials, using the pinned Podman runner:

```bash
: "${TEST_DATABASE_URL:?set the isolated PostgreSQL test URL}"
bash scripts/pod.sh go test -race -count=1 ./internal/control -run '^TestCoreActivation'
bash -n scripts/activate-core.sh
bash scripts/pod.sh shellcheck scripts/activate-core.sh
```

When the services use a private Podman network, also export
`TEST_PODMAN_NETWORK`; no host port is needed. Without `TEST_DATABASE_URL`, Go
integration tests skip and are **not** activation evidence. Database tests do
not certify a gateway: activation still requires the installation's real
management, transport, edge-health and cleanup acceptance evidence below.

## Install and activate a regional

Use a new host for the first regional gate. Do not repurpose or drain the only
principal while validating the regional profile.

1. Create the inactive cluster and `enrolling` node in Control.
2. Issue a one-use enrollment token and install it privately on the regional.
3. Install only public Control and transport trust on the regional.
4. Issue the exact management and observability server certificates.
5. Permit management TLS and TCP/9443 only from the principal's private path.
6. Deploy the `core-node` profile from the already verified bundle.
7. Confirm Core consumed and removed the plaintext token while retaining its
   mode-0600 node identity.
8. Confirm signed heartbeat, desired/observed revision and compatible version.
   The principal renewer must create and the node must observe a fresh lease
   before placement is enabled; do not extend `expires_at` directly in SQL.
9. Register the server and explicit transport inventory in Control.
10. Test signed add, list and conditional remove of a real test peer.
11. Confirm central Prometheus scrapes the regional and no metrics endpoint is
    public.
12. Exercise transport authentication, traffic, DNS, revocation, kill switch,
    restart and cleanup before setting certification and activation state.

The regional must never receive a database URL or password, Authentik secret,
Control data-encryption key, Control private signing key, Prometheus client key
or client-CA signing key. A node-reported certification value is informational;
only the central transport inventory can certify a transport.

## Upgrade order

Every upgrade uses a new immutable version and bundle. Do not modify a running
Quadlet to follow a tag.

1. Review compatibility, migration head, release manifest and all supply-chain
   evidence.
2. Record current image digests, desired revision, unit snapshot locations,
   database schema version and health state.
3. On the principal, create a custom-format backup and prove an isolated
   restore before any mutation. The protected deployer performs this gate
   automatically when it finds an existing principal database.
4. Drain and upgrade one non-principal node using the approved version tags
   after validating their resolved digests against the lock.
5. Verify signed management, heartbeat, desired/observed convergence, metrics
   and each advertised transport; then restore placement.
6. Repeat one regional at a time.
7. Upgrade the principal last. Its one-shot migrator completes before the new
   Core and Control start.
8. Require the strict public edge probe, candidate discovery and client smoke
   before declaring the upgrade complete.
9. Retain the pre-upgrade backup and deployment records until the acceptance
   window closes; remove them only under the approved retention policy.

The current Actions job targets one host. Additional regional invocations must
reuse the exact published bundle and image lock and receive their own approval and
evidence. Republishing a tag for another host is forbidden.

## Rollback

The deployer records rollback paths before mutation. On failure it attempts to
restore the prior `.env`, rootless/rootful unit directories, Nginx files and
firewall rules introduced by that attempt. It retains the failed configuration
for inspection.

| Failure point | Expected result |
| --- | --- |
| Bundle, signature, input or SSH validation | No host application mutation |
| Backup or isolated restore gate | Deployment stops before environment or unit changes |
| Quadlet render, install, Nginx, firewall or smoke | Previous configuration and units are restored where they were changed |
| Migration succeeded but later startup failed | Application configuration rolls back; the database remains at the forward schema |
| Data corruption or operator-directed point recovery | Automatic rollback is forbidden; use the explicit database recovery procedure |

For a manual unit rollback, use the exact snapshot printed by the installer:

```bash
sudo -u midorivpn bash deploy/host/rollback.sh \
  --backup-dir /home/midorivpn/.local/state/midorivpn-deploy/backups/APPROVED-rootless \
  --target-dir /home/midorivpn/.config/containers/systemd/midorivpn \
  --restart
```

Rootful gateway rollback uses `--scope rootful` as root and the exact recorded
system snapshot. Environment, Nginx and firewall have their own recorded
rollback artifacts. Never choose the newest-looking directory by name during
an incident; use the deployment record for the failed run.

Database migrations are not automatically reversed, and the deployer never
restores live data. An explicit database restore requires an outage decision,
a verified dump and SHA-256, an isolated restore test, a post-backup write-loss
assessment and separate operator authorization.

## Recovery scenarios

### Principal or database unavailable

Established regional tunnels may continue with their last-known-good state,
but new sessions and policy changes remain unavailable. Restore the central
database, the exact `CONTROL_DATA_ENCRYPTION_KEY`, Control signing identity,
OIDC configuration and private CA state before reopening provisioning. A
regional cannot replace the principal. If the data-encryption key is lost,
stored recoverable WireGuard PSKs cannot be decrypted.

### Regional unavailable

Stop new placement, drain or revoke the node centrally and preserve its
desired state and evidence. Other healthy Cores and the principal continue.
Rebuild the regional with its last approved version tag and locked digest, and either its protected
node state or a newly enrolled identity; never clone one node identity onto a
different active node.

### Registry unavailable

Running containers already loaded under approved version tags continue with
`Pull=never` without GHCR. New installation and upgrade stop until those exact
private tags resolve to their recorded digests again. Do not make a package
public, substitute a tag or build on the host as a recovery shortcut.

### Bad desired state or signing failure

Core rejects an invalid, expired, wrongly targeted or rolled-back bundle and
keeps its last-known-good revision. Investigate the bounded observed error,
the `midori_vpn_desired_state_renewal_errors_total` counter and the latest
lease-expiry timestamp. The principal normally renews a verified unchanged
intent six hours before expiry and can recover an expired lease at startup. If
renewal remains blocked, correct central intent and issue a new monotonic
revision. Never edit historical validity in PostgreSQL or disable signature or
replay checks.

### Failed certificate renewal

Keep the prior valid certificate and configuration, correct the ACME or file
permission problem and rerun validation. Do not disable TLS verification or
publish a private listener to restore monitoring.

## Credential and certificate rotation

Every rotation has a written owner, expiry and rollback point. Use overlap for
public trust whenever the protocol supports it.

| Material | Rotation procedure |
| --- | --- |
| Deployment SSH key | Add the replacement public key on the host, verify its fingerprint out of band, update the protected private-key secret, test strict login, then remove the old authorization |
| SSH host key | Verify the new fingerprint through an independent channel, update the protected known-hosts secret, then retire the old host key |
| GHCR pull token | Create a read-only replacement, verify private package pull, update the protected secret, then revoke the old token |
| OAuth, Redis, Grafana and application passwords | Change the backing service and the matching secret fragment as one maintenance operation, apply the partial patch, restart only affected units and verify readiness before revoking the old credential |
| Control management and transport signing identity | Add replacement public trust to every Core first, deploy the new signer/`kid`, prove signed management and transport traffic everywhere, then remove the old public key |
| Node enrollment token | Revoke an unused token and issue a new one; tokens are one use and their plaintext is removed after successful enrollment |
| Public TLS certificate | Use Certbot renewal and the installed deploy hook; validate Nginx and reload the affected gateway without changing image identity |
| Observability server/client CA | Follow the overlapping server-CA and client-CA sequence in `deploy/OBSERVABILITY.md`; prove all targets `up` before removing old trust |
| Client VPN CA | Distribute replacement public trust and CRL first, issue and test new device certificates, revoke the former chain, and never copy the signing key to a gateway |

`CONTROL_DATA_ENCRYPTION_KEY` is recovery-critical and currently has no
zero-downtime multi-key rotation contract. Back it up separately from the
database. Suspected compromise requires a dedicated, tested re-encryption
maintenance procedure; merely replacing the Environment secret would make
existing ciphertext unreadable and is forbidden.

## Observability and post-deployment checks

Prometheus and Grafana are private operational services. Grafana is reached
through an SSH tunnel or equivalent private channel. Core metrics use TLS 1.3,
a private client CA and the exact authorized Prometheus URI SAN. The public
Nginx vhost must return 404 for `/metrics`.

After each deployment, record without secrets:

- release tag, four source commits and Core/Control digests;
- bundle SHA-256 and target profile;
- database backup/restore gate result and migration version;
- active unit state and restart counts;
- local readiness and exact public 204 edge response;
- desired/observed revision, lease expiry/renewal counters, heartbeat age and
  node compatibility;
- private Prometheus target state and relevant alert status;
- enabled transport authentication, traffic and cleanup result; and
- every rollback snapshot retained by the run.

At minimum, investigate any alert for unavailable database/pool, stale
heartbeat, desired/observed drift, incompatible Core version, desired-signature
failure, desired lease approaching one hour, renewal errors, capacity
exhaustion, reconciliation divergence, cleanup backlog or pending peer
operations. A failed Core observation must remain an error and must never be
displayed as zero peers.

## Production acceptance checklist

A source commit or green build alone is not production certification. Before
declaring 2.0.0 ready, require all of the following:

- all four annotated tags and commits match the reviewed release manifest;
- Core and Control remain private, are pulled by exact release tag and verify
  by resolved digest, signature, provenance and SPDX attestation;
- the production principal was created from the approved empty-database path;
- backup, isolated restore, migration, restart and configuration rollback were
  exercised on the approved release;
- no database, Redis, plain application HTTP, metrics or administrative port is
  publicly reachable;
- the public edge route returns the strict 204 contract and candidate
  `probe_url` values match it;
- one independent regional passes enrollment, management, observability,
  transport and failure-isolation gates before activation;
- automatic Desktop and Extension selection reconnects between two eligible
  Cores without multiplying device identity;
- a principal outage demonstrates established-tunnel continuity and the
  documented fail-closed behavior for new sessions;
- secret and certificate recovery material is escrowed and at least one
  rotation/rollback drill is evidenced; and
- artifacts installed on every target match the frozen digests and hashes.

Stop the rollout on any missing or ambiguous item. Do not weaken an identity,
health, backup, visibility or review gate to complete a deployment.

## Public documentation and private evidence

Keep this repository environment-neutral. Public documentation may contain
placeholder domains, role names and example paths only. Real hostnames, IP
addresses, SSH aliases, inventory, database counts, fingerprints, incident
evidence and deployment results belong in the private operational record, not
in commits, bundles, Actions logs or release notes. Secrets and private keys do
not belong in either location.
