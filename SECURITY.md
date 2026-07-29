# SecureStep Partner Security Policy

## Purpose

This policy defines how security vulnerabilities affecting this repository must be reported and how SecureStep Partner handles those reports. It applies to source code, scripts, Infrastructure as Code, automation, GitHub Actions workflows, configuration examples, and documentation maintained in this repository.

The [Cloud Incident Response Cheatsheet](https://github.com/SecureStepPartner/cloud-incident-response.github.io) is a technical investigation reference. It does not replace this policy or an authorized incident-response plan.

## Supported versions

Security fixes are provided for:

- The current default branch.
- The latest supported release, when releases are published.
- Other versions only when a repository maintainer explicitly identifies them as supported.

Older branches, forks, archived versions, and unsupported releases may not receive security updates.

## Reporting a vulnerability

Do **not** disclose a suspected vulnerability through a public issue, pull request, discussion, commit, or social-media post.

Use GitHub's private vulnerability reporting when it is available:

[Report a vulnerability privately](https://github.com/SecureStepPartner/SiteScanner/security/advisories/new)

If private reporting is unavailable, notify a SecureStep Partner repository administrator through an existing authorized business communication channel. Mark the message **Confidential - Security Report**. Do not transmit passwords, private keys, tokens, customer data, or other secrets in the initial report.

Include, when available:

- Affected repository, branch, release, file, or workflow.
- A clear description of the vulnerability and potential impact.
- Reproduction steps or a minimal proof of concept.
- Relevant logs, timestamps, and indicators with secrets redacted.
- Suggested remediation or compensating controls.
- Whether active exploitation or exposed credentials are suspected.

If credentials or secrets appear exposed, stop testing and report immediately. SecureStep Partner will validate and revoke or rotate affected credentials through authorized channels.

## Response expectations

SecureStep Partner will make a reasonable effort to:

- Acknowledge a complete report within three business days.
- Complete initial severity and scope triage within seven business days.
- Provide periodic updates while remediation is active.
- Coordinate disclosure after affected users have had a reasonable opportunity to remediate.

Timelines may vary with severity, exploitability, customer impact, third-party dependencies, and evidence availability. Receipt of a report does not guarantee acceptance, a bounty, or public recognition.

## Researcher conduct

To support coordinated and responsible disclosure:

- Test only systems and repositories you are authorized to assess.
- Use the minimum interaction needed to demonstrate the issue.
- Do not access, alter, retain, or disclose customer or personal data.
- Do not establish persistence, perform lateral movement, degrade availability, or conduct social engineering.
- Do not use destructive testing, denial of service, or high-volume automated scanning.
- Preserve relevant evidence and maintain confidentiality until disclosure is coordinated.

Good-faith research that follows this policy will be evaluated based on the facts and applicable law. This policy does not authorize testing of third-party services, customer environments, or systems outside SecureStep Partner's control.

## Maintainer response principles

For accepted reports, maintainers will follow a risk-based response process aligned with NIST incident-response practices:

1. Validate the report, establish scope, and preserve available evidence.
2. Contain exposed identities, sessions, credentials, workflows, and integrations.
3. Remove the root cause through reviewed and tested changes.
4. Recover from trusted code and configuration, then validate security controls.
5. Document lessons learned and track corrective actions.

Cloud and platform logs are not retroactive. Responders must preserve available audit, identity, workflow, and control-plane evidence before retention windows expire.

## Public disclosure

Public disclosure must be coordinated with SecureStep Partner. When appropriate, SecureStep Partner may publish a GitHub Security Advisory, assign or request a CVE, acknowledge contributors, and document affected and fixed versions.
