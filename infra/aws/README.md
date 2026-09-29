# AWS sandbox setup

Use a dedicated disposable Linux host and AWS account. Read the
[security limitations](../../SECURITY.md) before starting. Run the commands below
from the repository root after completing the [installation](../../README.md#quickstart).

## 1. Choose a sandbox account

Use an existing disposable member account in AWS Organizations, in `us-east-1`.
Do not use a shared or production account: cleanup can delete resources outside
the current trial.

One account is enough to get started. Running against an existing sandbox does
not require management-account access.

## 2. Set permissions and guardrails

Configure an AWS Identity Center permission set or assumed role that allows:

- Creating, inspecting, and deleting resources used by the cases.
- Creating and deleting IAM roles/policies, using `iam:PassRole`, and creating service-linked roles.
- Reading cloud state for evaluation and cleanup checks.

The reference setup used sandbox administrator permissions constrained by the
supplied [service control policy](sandbox-scp.json). Review the policy, then have
an authorized administrator attach it to the sandbox account or its dedicated OU.
AWS Organizations must have all features enabled to use SCPs.

**An SCP limits permissions; it does not grant them.** This policy restricts
services, regions, expensive instance/database classes, and selected dangerous
operations. It does not cap spending or prevent every form of credential issuance.
See [Security](../../SECURITY.md#aws-permissions-and-cleanup) for the remaining limits.

## 3. Configure CloudGym

Copy the example configuration:

```bash
cp .cloudgym/aws.example.toml .cloudgym/aws.local.toml
```

Edit `.cloudgym/aws.local.toml` with your sandbox's details:

```toml
[aws]
profile = "cloudgym-sandbox"
account_id = "000000000000"        # Replace with your 12-digit sandbox account ID.
region = "us-east-1"
role_name = "SandboxAdministrator" # Your Identity Center permission-set name.
access = "sso"
```

For an assumed organization role, use `access = "org-role"` and set `role_name`
to that role's name. The local configuration is gitignored; keep credentials out of it.

## 4. Authenticate and verify

For Identity Center, log in with the profile configured above:

```bash
aws sso login --profile cloudgym-sandbox
uv run bench doctor
```

For an assumed role, authenticate its source profile through your normal AWS
workflow, then run `uv run bench doctor`.

Resolve any configuration or identity failures before continuing. The harness
checks the account and role through STS before Terraform or agent execution.
`bench doctor` does not verify model access or that bubblewrap can run.

## 5. Run a smoke trial

With your agent CLI authenticated and the checkout clean:

```bash
uv run bench run experiments/smoke.yml --allow-aws --slots 1
uv run bench report experiments/smoke.yml
```

Live runs incur AWS and model charges. Configure billing alerts before scaling.
Service quotas, account age, and regional availability can also prevent cases
from running; retain those failures in your run records.

See [Experiments](../../docs/experiments.md) for model selection, development
checkouts, and larger batches.

## 6. Check cleanup

Inspect the pool and preview any remaining account-wide deletions:

```bash
uv run bench pool
uv run sandbox-clean --allow-aws --dry-run
```

After reviewing the deletion plan, reset your dedicated sandbox if needed:

```bash
uv run sandbox-pool reset cloudgym-sandbox --allow-aws
```

The sweeper preserves selected AWS-managed baseline resources, but its IAM cleanup
covers roles and local policies, not users or access keys. A successful sweep is
not proof that all persistent access has been removed. Inspect cleanup evidence
after failures and interruptions.

## Optional: add more sandbox accounts

The `[aws.pool]` configuration supports additional accounts, with one concurrent
cell per account. Creating accounts requires separate Organizations permissions;
it is not needed for the steps above.

Pool coordination is local to one host. Do not run independent hosts against
the same sandbox accounts. See the comments in
[aws.example.toml](../../.cloudgym/aws.example.toml) for the configuration fields.
