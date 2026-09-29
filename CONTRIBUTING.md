# Contributing to CloudGym

Contributions to documentation, runtime behavior, agent integrations, and benchmark
cases are welcome. Keep changes focused and explain how they affect users or
experiment results.

## Table of contents

- [Development setup](#development-setup)
- [Changing benchmark cases](#changing-benchmark-cases)
- [Pull requests and issue reports](#pull-requests-and-issue-reports)
- [Licensing](#licensing)

## Development setup

From a checkout of the repository:

```bash
uv sync --frozen --group dev
uv run pytest tests -q
uv run bench run experiments/smoke.yml --dry-run
```

Python 3.13+ is required. Tests use fake AWS services and agents; the offline suite
does not need cloud credentials or provider access. Some tests start local servers,
so allow loopback sockets. Install OPA to run the oracle tests; they skip when it
is absent. Live bubblewrap tests require Linux and working namespace support.

[CI](.github/workflows/ci.yml) runs the full test suite, case oracle fixtures,
and an offline smoke preview on pushes to `main` and updates to non-draft pull
requests, including when a draft is marked ready for review. It uses Python 3.13
on Linux with OPA and bubblewrap installed. Tests run with external networking
blocked and loopback enabled for fake services; no AWS or model credentials are needed.

For a focused change, run the relevant tests, for example:

```bash
uv run pytest tests/bench/test_spec.py -q
uv run pytest tests/test_aws_safety.py tests/agents/test_sandbox.py -q
```

Use a dedicated disposable Linux host and AWS account for any live verification.
Live runs are a separate step and incur charges. Read [Security](SECURITY.md) and
[AWS setup](infra/aws/README.md) before running them.

## Changing benchmark cases

Start with [Add your first case](docs/authoring-cases.md) for a worked tutorial.
Read the [case layout](docs/benchmark.md#case-layout), preserve upstream provenance,
and update fixtures alongside changes to tasks, policies, or oracles.

```bash
uv run validate-case cases/aws/iac-eval-149-iam-role-001
uv run pytest tests/cases/test_oracles.py -q
```

The validator predates some cases; describe any unresolved findings and check the
corresponding oracle fixtures. Validation imports case Python modules, so only
validate code you trust on your development host. Add a new case to
`cases/manifest.json` when it is ready to join the active benchmark.

Keep frozen research configurations stable. Use a new configuration and batch
name for new experiments. Explain whether a change affects historical results,
requires rerunning cells, or changes the meaning of a score.

## Pull requests and issue reports

Include the problem, the resulting behavior, and the checks you ran. For bugs,
provide a minimal reproducer, relevant tool versions, and sanitized logs. For
behavior changes, add focused regression coverage when appropriate. Documentation
changes should keep commands, paths, and examples consistent.

Do not commit credentials, local AWS configuration, Terraform state, provider
binaries, or raw run outputs. Logs and transcripts may contain sensitive data;
review their contents before sharing them. Keep fixes for unrelated issues in
separate pull requests.

## Licensing

Contribute only material you have permission to share. Original software and
documentation outside `cases/` use the [MIT License](LICENSE); benchmark material
under `cases/` uses [CC BY 4.0](cases/LICENSE.md), except where otherwise noted.
Retain third-party attribution and identify changes to upstream material.
