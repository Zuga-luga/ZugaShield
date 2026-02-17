# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | Yes       |

## Reporting a Vulnerability

If you discover a security vulnerability in ZugaShield, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please email: **antonio@zuga.dev**

Include:
- Description of the vulnerability
- Steps to reproduce
- Impact assessment
- Suggested fix (if you have one)

## Response Timeline

- **Acknowledgment**: Within 48 hours
- **Assessment**: Within 1 week
- **Fix**: As soon as possible, depending on severity

## Scope

The following are in scope:
- Bypass of any detection layer (prompt injection that evades Prompt Armor, etc.)
- False negatives in signature matching
- Denial of service via crafted inputs
- Information disclosure through error messages
- Vulnerabilities in the MCP server

The following are out of scope:
- False positives (these are bugs, not security issues — open a regular issue)
- Attacks that require access to the host machine
- Social engineering

## Recognition

We're happy to credit security researchers in our changelog and README. Let us know how you'd like to be credited.
