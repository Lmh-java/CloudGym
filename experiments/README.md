# Experiment configurations

Start with [smoke.yml](smoke.yml): one IAM case, one trial, and your Claude CLI's
default model. Preview it without AWS or model calls:

```bash
# From the repository root:
uv run bench run experiments/smoke.yml --dry-run
```

Copy it and choose a new `batch` name to create your own experiment. The
`paper-config-*` files preserve the frozen research comparisons and their original
batch identifiers. Each schedules 1,530 cells; all four schedule 6,120 before retries.

See the [experiment guide](../docs/experiments.md) for configuration fields, model
selection, running batches, reporting, and costs. Live execution requires the
[AWS setup](../infra/aws/README.md) and attention to [security limitations](../SECURITY.md).
