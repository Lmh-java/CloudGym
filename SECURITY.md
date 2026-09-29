# Security and safe operation

CloudGym executes agent-generated commands and creates, changes, and deletes real
cloud infrastructure. It is research software with known isolation limitations.
Run it on a dedicated disposable Linux host against a dedicated disposable AWS
account, using credentials intended only for these experiments.

## Execution boundaries

The harness verifies the configured AWS account and role before live execution.
Live commands require `--allow-aws`. By default, agents receive dummy AWS credentials
and send requests through a local interception proxy. Linux batch runs require
bubblewrap and test that selected host paths are hidden before deploying resources.

These controls do not establish a hardened boundary against a malicious agent.
Current limitations include:

- Agent environment filtering removes selected AWS variables but can retain
  unrelated environment secrets. Start from an environment without unrelated tokens.
- Host CLI state directories are mounted writable, including authentication and
  configuration outside the per-run session overlays. Use dedicated CLI logins
  and a disposable host, not your everyday development account.
- Proxy restrictions primarily operate at service granularity. IAM-enabled cases
  can permit credential-creation operations if the AWS role and effective policies
  allow them; independently issued credentials can bypass the proxy's trace.
- Standalone `run-case` defaults to `--sandbox auto`, and non-Linux batch runs can
  proceed without confinement. Use Linux with working bubblewrap; specify
  `--sandbox required` for standalone live runs.
- Evaluated agents share the host network. MCP endpoints have no application-configured
  per-run authentication, so localhost should not be treated as a boundary between
  mutually untrusted processes or concurrent agents.

Case modules and lifecycle commands also execute trusted project code. Inspect
third-party cases before running or validating them. Keep proxy and MCP endpoints
on loopback; do not expose them as public services.

## AWS permissions and cleanup

The supplied [service control policy](infra/aws/sandbox-scp.json) limits some
services, regions, and expensive operations. It does not grant permissions, cap
spending, or prevent every form of credential issuance. Review effective IAM and
organization policies for your account before use.

The account-wide cleanup sweeper can delete resources outside the current trial.
It does not enumerate every possible resource type; in particular, its IAM sweep
covers roles and local policies, not IAM users and access keys. Do not treat a
successful sweep as proof that an untrusted agent left no persistent access.

Inspect cleanup evidence and billing after runs, especially after interruptions.
Do not use a shared or production AWS account. See [AWS setup](infra/aws/README.md)
for account configuration and the cleanup workflow.

## Sensitive files and reports

Keep local configuration, credentials, Terraform state, and run outputs out of
Git. The repository ignores common generated paths, but custom output paths need
separate care. Transcripts, API evidence, and state snapshots may contain secrets
or private resource data; review and sanitize them before attaching them to reports.

Use synthetic credentials and mock services when documenting or testing security
issues. Never include live credentials or private account data in public issues.
