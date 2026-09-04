# Contributing to MidoriVPN Core

MidoriVPN 2.0.0 is unreleased. Contributions should preserve the documented
security boundaries and must not describe an implemented feature as released
or a tested component as certified on every deployment.

## Before starting

- Use a public issue for bugs and proposed behavior changes.
- Report vulnerabilities privately according to [SECURITY.md](SECURITY.md).
- Keep deployment credentials, private endpoints, logs and environment files
  out of commits and issue attachments.
- Keep changes focused; explain any public API, migration, security or
  operational compatibility impact.

## Development environment

The supported workflow uses rootless Podman and the pinned workspace images.
Host-installed Go and Node toolchains are not required.

```bash
bash scripts/pod.sh build-images
bash scripts/pod.sh go test -race ./cmd/... ./internal/...
bash scripts/pod.sh go vet ./cmd/... ./internal/...
bash scripts/pod.sh staticcheck ./cmd/... ./internal/...
bash scripts/pod.sh govulncheck ./cmd/... ./internal/...
bash scripts/check-openapi.sh
bash scripts/pod.sh debt
```

Run `bash scripts/test-migrations.sh` when a schema or repository contract
changes. Applied migrations are immutable: add matched up/down files instead
of editing an existing migration.

## Change requirements

- Update `docs/openapi.yaml`, consumers and tests together when a route,
  payload, response or error code changes.
- Preserve fail-closed behavior for authentication, authorization, peer state,
  trust, transport health and secret handling.
- Use the newest compatible dependency release; do not silence an advisory by
  downgrading to an obsolete line.
- Keep generated artifacts, local evidence and secrets out of Git.
- Update the `2.0.0 - Unreleased` changelog section for user-visible,
  operational or security-relevant changes.

Before submitting, run the checks relevant to the changed surface and
`git diff --check`. A pull request should describe behavior, risk, test results,
schema or rollback considerations and any intentionally deferred work.

## License

By contributing, you agree that your contribution is licensed under
AGPL-3.0-or-later, as described in [LICENSE](LICENSE).
