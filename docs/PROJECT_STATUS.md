# MidoriVPN 2.0.0 project status

Reviewed locally on **2026-10-21**. Version 2.0.0 remains **Unreleased** and the
final release remains blocked. This review inspected local source and
documentation; it did not contact deployment hosts, registries, CI or stores.

## Implementation and acceptance

The source includes persistent device identity, durable peer operations and
reconciliation, signed node enrollment and desired state, scoped Ed25519
transport credentials, private observability, deployment tooling and API
contract tests. Implementation and earlier component acceptance do not certify
a new independent regional deployment or the final rebuilt artifact set.

| Gate | Recorded state | Required completion |
|---|---|---|
| Earlier implementation phases | Historical completion records retained | Revalidate checks relevant to the final source and artifacts |
| Private management network (NET-01) | In progress | Current network/TLS, access restrictions and restart/recovery evidence |
| Independent regional acceptance (VAL-04) | Blocked by NET-01 | Enrollment, convergence, transport traffic/DNS, cleanup, outage isolation and real failover |
| Performance and clients (VAL-05) | Pending | Agreed workload and acceptance thresholds, measured p50/p95, throughput/CPU and final client installation checks |
| PostgreSQL final acceptance (VAL-06) | Pending | Final-schema restore, least privilege, timeouts, pool/lock pressure and restart recovery |
| Coordinated final candidate (REL-04) | Blocked | Completed preceding gates, frozen commits, repeated builds, signatures, SBOM/provenance, smoke and rollback |
| External publication (CLS-05) | Blocked | Final acceptance and specific authorization for each publication channel |

The regional failover gate requires automatic Desktop/extension reconnection
within 30–60 seconds, one active session and eventual cleanup without repeated
switching. Manual selection must stay on the selected server. Established
tunnels must survive a Control outage; this is not high availability for
Control or PostgreSQL.

## Security and evidence freshness

The extension's two development-tooling exceptions for image-size advisories
GHSA-w3rx-r6r6-pgpr and GHSA-5p2g-fcmc-qvqq expired on **2026-10-04**. Its local
audit policy rejects expired exceptions. Revalidation is required before
closing client validation and final release preparation. This review did not
run a fresh npm audit, determine current upstream fix availability, extend
exceptions or change mitigation code. It does not establish a production
runtime vulnerability.

The deployment evidence used for this reconciliation was last recorded in
September 2026. Host state, certificates, registry access and vulnerability
reports need current verification before rollout. Earlier green CI results
remain historical evidence with their original scope and date.

Locally, the container-free Podman runner layout tests and git diff --check
passed. Podman was unavailable in PATH, so the complete Go/race, PostgreSQL,
frontend, build and security matrices were not rerun.

## Next release preparation

Complete private management readiness, then certify the independent regional
node and failure behavior. Close performance/client and database acceptance
before producing the final coordinated candidate. Select a fresh candidate
version only after checking existing refs and explicit release authorization;
historical candidate numbers in examples must not be reused or moved.

Operational acceptance criteria are in
[CENTRAL_CONTROL_ARCHITECTURE.md](CENTRAL_CONTROL_ARCHITECTURE.md),
[PRODUCTION_DEPLOYMENT.md](PRODUCTION_DEPLOYMENT.md) and
[RELEASE_SUPPLY_CHAIN.md](RELEASE_SUPPLY_CHAIN.md). Private task history and
deployment details remain outside public documentation.
