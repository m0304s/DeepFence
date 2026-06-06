# Security Policy

DeepFence is an experimental IDS/IPS pipeline for defensive security research,
education, and authorized network monitoring.

## Supported Scope

Security reports are welcome for issues in the DeepFence source code, including:

- Unsafe parsing or processing of Suricata `eve.json` events
- Incorrect handling of configuration, secrets, or environment variables
- Bugs that may cause unsafe blocking decisions
- Vulnerabilities in the runtime pipeline, policy engine, or storage integration

This project is not intended for unauthorized scanning, exploitation, traffic
interception, or offensive use against systems you do not own or operate with
explicit permission.

## Reporting a Vulnerability

If you find a security issue, please report it privately before opening a public
issue. Include:

- A clear description of the issue
- Steps to reproduce
- Affected files or components
- Expected impact
- Any suggested mitigation, if available

If the repository owner has not published a dedicated security contact yet, use
GitHub's private vulnerability reporting feature when available. Otherwise,
open a minimal public issue that does not include exploit details and ask for a
private contact channel.

## Responsible Use

Use DeepFence only in environments where you have permission to monitor and
control traffic. Test automatic blocking in an isolated environment before using
it on a real network.

The current model and policies are experimental. DeepFence should not be used as
the only security control for a production environment.
