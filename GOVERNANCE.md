# Governance

## Project Lead

**Antonio Zugaldia** ([@Zuga-luga](https://github.com/Zuga-luga)) is the project lead and final decision-maker (BDFL) for ZugaShield.

## Decision Making

- **Minor changes** (bug fixes, signature updates, doc improvements): Any maintainer can merge after one approval.
- **Feature additions** (new layers, integrations, config changes): Requires project lead approval.
- **Security-critical changes** (detection logic, integrity verification, fail-closed behavior): Requires project lead approval + review from at least one other maintainer. Changes must include tests demonstrating the security property.

## Contributing

Anyone can contribute. See [CONTRIBUTING.md](CONTRIBUTING.md) for setup and guidelines.

**Path to maintainer**: Contributors who demonstrate consistent, high-quality contributions (3+ merged PRs with tests) may be invited as maintainers with write access.

## Security

Vulnerabilities are handled through responsible disclosure. See [SECURITY.md](SECURITY.md).

Security-critical PRs are never merged without:
1. A test that reproduces the vulnerability
2. A test that proves the fix works
3. Review from the project lead

## Releases

- Releases follow [Semantic Versioning](https://semver.org/)
- Only the project lead can publish to PyPI
- All releases are built from CI (never from a local machine)
- Signature files in releases are signed with Ed25519

## Communication

- **Issues**: Bug reports, feature requests, bypass reports
- **Discussions**: Ideas, threat intelligence sharing
- **Security reports**: antonio@zuga.dev (see SECURITY.md)
