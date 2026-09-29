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

Use a dedicated disposable Linux host and AWS account. Live runs incur charges,
and cleanup can delete resources across the account. Read the
[security limitations](SECURITY.md) before running.

## Learn more

- [Experiments](docs/experiments.md) — configuration, results, and costs.
- [Benchmark](docs/benchmark.md) — cases, provenance, and reproducibility.
- [Contributing](CONTRIBUTING.md) — development and testing. Contributions welcome!

## License

Original software: [MIT](LICENSE). Benchmark cases: [CC BY 4.0](cases/LICENSE.md).
See [third-party notices](THIRD_PARTY_NOTICES.md) for attribution and exceptions.
