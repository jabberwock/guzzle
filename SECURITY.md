# Security Policy

## Scope

Guzzle is a local desktop application. It runs entirely on your machine — there is no Guzzle server, no telemetry, and no cloud backend. There is no Guzzle server and no telemetry.

When you trigger AI harness or PoC generation, the relevant source code and function signature are sent directly to the AI provider you configured (DeepSeek, Claude, OpenAI, Ollama, etc.). No other data leaves your device, and nothing is sent without an explicit action on your part. API keys are stored in your OS keychain, not in the application or any config file.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.2.x   | Yes       |
| < 0.2   | No        |

## Reporting a Vulnerability

If you discover a security vulnerability in Guzzle, please **do not open a public issue**. Instead, report it privately through GitHub's security advisory system:

**[Report a vulnerability](https://github.com/jabberwock/guzzle/security/advisories/new)**

Please include:
- A description of the vulnerability and its potential impact
- Steps to reproduce or a proof-of-concept
- The Guzzle version and OS you tested on

You can expect an initial response within **72 hours**. If the issue is confirmed, a fix will be prioritized and a patched release issued as soon as practical.

## What Qualifies

Given Guzzle's local-only nature, relevant security issues include:

- **Malicious corpus/crash files** triggering unintended code execution in Guzzle itself
- **Path traversal** in crash file handling or corpus directory resolution
- **AI prompt injection** via crafted source files leading to harmful harness output
- **Keychain/credential exposure** — API keys leaking to logs, temp files, or the filesystem
- **Arbitrary command execution** via crafted compiler flags or binary paths

Out of scope: vulnerabilities in the target binary you are fuzzing (that's the point of the tool), issues in third-party dependencies (report those upstream), or findings that require physical access to the machine.

## Dependency Security

Guzzle's Rust backend dependencies can be audited with:

```bash
cargo install cargo-audit
cargo audit
```

Frontend dependencies:

```bash
pnpm audit
```
