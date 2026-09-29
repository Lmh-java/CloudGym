# CloudGym

A benchmark for cloud agents working with concurrent infrastructure changes.
CloudGym runs agents against real AWS tasks, introduces interference from other
actors, and evaluates whether the agents complete their tasks correctly.

- **102 AWS cases** with infrastructure, policies, and automated scoring.
- **Claude and Codex support**, with SDK, Terraform, CLI, and hybrid tool access.
- **Experiment tooling** for batch runs, transcripts, reporting, and cleanup.

## Quickstart

Requires Python 3.13+ and [uv](https://docs.astral.sh/uv/). From the repository root:

```bash
uv sync --frozen --group dev
uv run bench run experiments/smoke.yml --dry-run
```

This previews one trial without calling AWS or a model.

## Run your first case

Complete the [AWS setup](infra/aws/README.md) and install the
[required tools](docs/experiments.md#requirements), then run:

```bash
uv run bench run experiments/smoke.yml --allow-aws --slots 1
uv run bench report experiments/smoke.yml
```

See the [smoke-run guide](docs/smoke-run.md) for expected output and result checks.

Use a dedicated disposable Linux host and AWS account. Live runs incur charges,
and cleanup can delete resources across the account. Read the
[security limitations](SECURITY.md) before running.

## Case in action

In the [Lambda smoke case](cases/aws/iac-eval-149-iam-role-001), the agent must
deploy `lambda.js` as `lambda_function_name`, using handler `lambda.handler` and
execution role `iam_for_lambda`. Other participants change the account as it works:

| Concurrent change | Required resolution |
| --- | --- |
| Another team claims the function name and adds an `orders-api` marking. | Use the existing function and preserve its marking. |
| A platform engineer updates the runtime to `nodejs24.x`. | Keep the account's runtime baseline. |
| A release engineer replaces the handler and code. | Restore the requested handler and supplied code. |
| An administrator switches the execution role. | Restore `iam_for_lambda` and preserve the shared role. |

The smoke run requires the agent to discover these rules through consultation.
It must inspect the changed state and reconcile competing requirements to finish
the deployment. The [scoring oracle](cases/aws/iac-eval-149-iam-role-001/evaluator/oracle.rego)
checks the final function's properties and preservation requirements, accounting
for which changes succeeded; it does not verify the deployed code's bytes.

## Learn more

- [Experiments](docs/experiments.md) — configuration, results, and costs.
- [Benchmark](docs/benchmark.md) — cases, provenance, and reproducibility.
- [Contributing](CONTRIBUTING.md) — development and testing. Contributions welcome!

## License

Original software: [MIT](LICENSE). Benchmark cases: [CC BY 4.0](cases/LICENSE.md).
See [third-party notices](THIRD_PARTY_NOTICES.md) for attribution and exceptions.
