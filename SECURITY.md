# Security policy

## Supported versions

MidoriVPN 2.0.0 is currently unreleased. Security fixes are applied to the
2.0.0 development line, but that source must not be treated as a supported
production release. Earlier release lines are no longer maintained by this
repository.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use the
[private GitHub security advisory form](https://github.com/goastian/midori-vpn-core/security/advisories/new).
If the report spans multiple MidoriVPN components, report it here and identify
the affected repositories.

Include, when available:

- the affected version, commit and deployment role;
- a minimal reproduction and the expected security boundary;
- the impact and any known preconditions;
- sanitized logs or traces with credentials, tokens, private keys, addresses
  and user data removed; and
- whether the issue is already public or under active exploitation.

Never send live credentials or production data. Use generated test material
and coordinate privately before sharing an exploit or proof of concept.

## Response and disclosure

The maintainers aim to acknowledge a complete report within three business
days and provide an initial triage within seven business days. Timing for a fix
depends on severity, affected releases and coordinated disclosure needs.

Please keep the report private until a fix and disclosure date are agreed.
Validated fixes must pass the relevant security and regression gates before a
release is announced. Credit is offered when requested and when doing so does
not expose sensitive information.

## Security boundaries

Reports about authentication, peer lifecycle, cryptographic material,
regional-node trust, network isolation, data recovery or release provenance
are in scope. Configuration questions without a demonstrated security impact
belong in normal project support channels.
