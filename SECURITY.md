# Security Policy

## Reporting a Vulnerability

The Greenbone community takes security bugs seriously. We appreciate your efforts
to responsibly disclose your findings, and will make every effort to acknowledge
your contributions.

### How to Report a Vulnerability

**Please do NOT report security vulnerabilities through public GitHub issues.**

Instead, please report them via email to: **security@greenbone.net**

Please include the following information in your report:

- Type of issue (e.g., buffer overflow, SQL injection, cross-site scripting, etc.)
- Full paths of source file(s) related to the manifestation of the issue
- The location of the affected source code (tag/branch/commit or direct URL)
- Any special configuration required to reproduce the issue
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue, including how an attacker might exploit it

This information will help us triage your report more quickly.

### What to Expect

- **Acknowledgment**: We will acknowledge receipt of your vulnerability report within
  3 business days.
- **Assessment**: We will confirm the vulnerability and determine its impact within
  10 business days.
- **Resolution**: We aim to release a fix within 30 days of confirming the vulnerability.
- **Disclosure**: We will coordinate with you on the timing of public disclosure.
  We prefer a coordinated disclosure, but will not unreasonably withhold permission
  for independent disclosure after 90 days.

### Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 23.x    | :white_check_mark: |
| < 23    | :x:                |

### Security-Related Configuration

For information on securely configuring OpenVAS Scanner, please refer to:

- [INSTALL.md](INSTALL.md) - Installation and setup instructions
- [doc/full_installation_guide.md](doc/full_installation_guide.md) - Full installation guide

### GPG Signing

Release artifacts are signed with the Greenbone Community Feed integrity key.
See the [README](README.md) for key details.
