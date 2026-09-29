# Your first smoke run

Run these commands from the repository root after
[installation](../README.md#quickstart). The
[smoke configuration](../experiments/smoke.yml) schedules one Claude trial of the
[Lambda case](../README.md#case-in-action), with interference, consultation, and hybrid tools.
It uses your Claude CLI's default model and gives the agent a 600-second budget.

## 1. Preview the trial offline

```bash
uv run bench run experiments/smoke.yml --dry-run
```

Expected output, with the checkout path replaced by `<repo>`:

```text
batch smoke  (sha256:97835f422ba0…)  → <repo>/artifacts/experiments/smoke

  smoke-consult/iac-eval-149-iam-role-001/t1       run_id=smoke-smoke-consult-iac-eval-149-iam-role-001-t1
    agent=claude model=- intercept=True awareness=consult modality=hybrid distractors=True timeout=600s poll=10s seed=iac-eval_149_iam_role case_dir=<repo>/cases/aws/iac-eval-149-iam-role-001
```

This confirms one scheduled cell: one arm, one case, and trial 1. `model=-` means
the CLI default, not a missing credential. The hash changes if you edit the
configuration. This preview makes no AWS or model calls and produces no verdict.

## 2. Run against your sandbox

Complete [AWS setup](../infra/aws/README.md), install the
[required tools](experiments.md#requirements), and authenticate Claude. Use a
dedicated disposable Linux host and AWS account, and read the
[security limitations](../SECURITY.md). Live runs incur charges.

```bash
uv run bench doctor
uv run bench run experiments/smoke.yml --allow-aws --slots 1
```

Use a clean checkout for a reproducible run. For local development, append
`--allow-dirty` and retain your source snapshot. Setup and cleanup add time beyond
the agent's 600-second budget.

After progress logs, a completed first run prints a batch summary shaped like
this **illustrative output**, not a recorded live result:

```json
{
  "batch": "smoke",
  "batch_dir": "<repo>/artifacts/experiments/smoke",
  "ran": 1,
  "outcomes": {
    "smoke-consult/iac-eval-149-iam-role-001/t1": "done"
  },
  "stopped": null
}
```

`done` means the run completed; the agent may still receive a `fail` verdict.
Rerunning resumes the same batch, so an already completed cell need not run again.
Use `--fresh` for a new timestamped launch.

## 3. Inspect the result

```bash
uv run bench status experiments/smoke.yml
uv run bench report experiments/smoke.yml
```

The report prints summary tables and writes `results.csv` and `summary.md`.
For the default launch, the main files are:

```text
artifacts/experiments/smoke/
  ledger.json
  results.csv
  summary.md
  smoke-consult-iac-eval-149-iam-role-001-t1/
    result.json
    agent/
    events.jsonl
    distractor-summary.json
    consult-summary.json
```

Check these fields in the CSV, alongside the run's `result.json` and transcripts:

| Field | How to read it |
| --- | --- |
| `status` | `completed` means the lifecycle finished. |
| `verdict` | `pass` or `fail` is the oracle's task score; a missing verdict is unscored. |
| `validity` | `valid`, `partial`, or `invalid` distinguishes usable runs from deviations or infrastructure failures. |
| `distractor_status` | Shows which programs succeeded, failed, or never fired. |
| `leaked` | `0` means no leftovers were detected by the leak check; blank means unavailable. |

A working smoke run can produce a valid `fail`: the agent did not solve the task.
Review `validity_reason` and `error` for partial or invalid runs. A clean leak
check has the coverage limits described in [Security](../SECURITY.md).

## 4. Verify the account is reusable

```bash
uv run bench pool
```

If the account is dirty or the run was interrupted, follow the
[cleanup steps](../infra/aws/README.md#6-check-cleanup) before reusing it.
See [results and scoring](experiments.md#results-and-scoring) for larger batches.
