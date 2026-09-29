# Running experiments

Start with the [README quickstart](../README.md#quickstart) and complete
[AWS setup](../infra/aws/README.md) before any live run. Commands below run from
the repository root. Read the [security limitations](../SECURITY.md) first.

## Requirements

Live runs require Linux with working `bubblewrap` (`bwrap`) namespace support,
Python 3.13+, `uv`, Terraform 1.5+, OPA 1.x, and AWS CLI v2. Install and authenticate
the `claude` and/or `codex` CLI you will evaluate; use Node.js 22+ for CLI
installations that need it. Use a dedicated disposable AWS account in `us-east-1`.

The reference environment used Terraform 1.15.4 and OPA 1.19.0. Python dependencies
are locked in `uv.lock`, and the AWS provider is locked in
`harness/terraform/aws/.terraform.lock.hcl`. Model access depends on your provider
account. `bench doctor` checks tools and AWS identity, but does not validate model
access or prove that bubblewrap works. Live runs require a clean Git checkout by
default; use `--allow-dirty` only for development runs without a commit pin.

## Create a configuration

Copy `experiments/smoke.yml` to `experiments/my-experiment.yml`, change its `batch`
name, and choose the agent and model you want to evaluate. Relative case paths
resolve from the configuration's directory. Omit `model` to use the agent CLI's
default; set it explicitly for comparisons you want to reproduce.

For example, this configuration compares three conditions on one case:

```yaml
batch: my-experiment
defaults:
  agent: claude
  timeout: 600
  poll_interval: 10
  trials: 1
  modality: hybrid
cases:
  - ../cases/aws/iac-eval-149-iam-role-001
arms:
  - {name: policy, awareness: none}
  - {name: consult, awareness: consult}
  - {name: control, distractors: false}
```

An *arm* is one experimental condition. A *cell* is one arm, case, and trial.
The example schedules three cells. `awareness: none` exposes no awareness tool;
with the default `policy: true`, the resolution policy is still in the prompt.
`consult` withholds that policy and exposes consultation instead. The control arm
turns off interference. Tool modalities are `hybrid`, `sdk`, `iac`, and `cli`.

```bash
uv run bench run experiments/my-experiment.yml --dry-run
uv run bench run experiments/my-experiment.yml --allow-aws --slots 1
uv run bench report experiments/my-experiment.yml
```

Use `agent: codex` for the Codex adapter. Each CLI must be installed and
authenticated independently. Never put credentials in experiment YAML.

Live runs require a clean Git checkout. Commit your configuration before running
an experiment you intend to reproduce. `--allow-dirty` permits development runs
without a commit pin; retain the source snapshot and configuration separately.

## Included configurations

| File | Comparison | Cases | Arms | Cells |
| --- | --- | ---: | ---: | ---: |
| [smoke.yml](../experiments/smoke.yml) | One case, CLI default model | 1 | 1 | 1 |
| [paper-config-1.yml](../experiments/paper-config-1.yml) | Control, policy in prompt, consultation; hybrid tools | 102 | 15 | 1,530 |
| [paper-config-2.yml](../experiments/paper-config-2.yml) | SDK, Terraform, CLI; consultation | 102 | 15 | 1,530 |
| [paper-config-1-t2.yml](../experiments/paper-config-1-t2.yml) | Second trial of configuration 1 | 102 | 15 | 1,530 |
| [paper-config-2-t2.yml](../experiments/paper-config-2-t2.yml) | Second trial of configuration 2 | 102 | 15 | 1,530 |

The `paper-config-*` filenames and batch identifiers are retained to identify the
frozen research configurations. Copy them to new files with new batch names for
custom experiments. Configuration 2's hybrid baseline is configuration 1's
consultation arm. All four configurations schedule **6,120 cells** before retries.
The `-t2` files use `trials_from: 2` and `trials: 2` to schedule only trial 2;
`trials` is the final trial index, not an additional number of trials.

The frozen configurations request `claude-haiku-4-5-20251001`, `claude-opus-5-5`,
`claude-fable-5`, `gpt-5.5`, and `gpt-5.6-sol`. These identifiers document the
configured experiments; access is not provided by this repository. Confirm access
before launching a batch. If a model is unavailable, use a separate configuration
and record the substitution. Fable is evaluated as an agent system, including its
model switching. Run records retain requested and reported models.

Preview a full configuration before launching it:

```bash
uv run bench run experiments/paper-config-1.yml --dry-run
uv run bench run experiments/paper-config-1.yml --allow-aws --slots 1
```

Run the remaining configurations the same way when ready. Use
`--only 'arm/case/t1'` to select cells; the selector supports glob patterns.

## Operating experiments

Rerunning `bench run` resumes the same batch's ledger. Choose a new batch name for
a different experiment. `--fresh` creates a separate timestamped launch.

```bash
uv run bench start experiments/smoke.yml --allow-aws --slots 1
uv run bench status experiments/smoke.yml
uv run bench logs experiments/smoke.yml
uv run bench stop experiments/smoke.yml
```

`bench start` runs detached. `bench stop --drain` allows active cells to finish
without starting new ones. One sandbox runs one cell at a time; additional
accounts increase throughput and simultaneous spend. Local pool state coordinates
processes on one host, not independent hosts using the same accounts.

The harness attempts teardown on completion and interruption. A failed leak check
marks the account dirty so it cannot be reused automatically. Inspect
`result.json`, cleanup logs, and the AWS console before reusing it.

```bash
uv run bench pool
uv run sandbox-clean --allow-aws --dry-run
# Inspect the deletion plan, then reset only your dedicated sandbox:
uv run sandbox-pool reset cloudgym-sandbox --allow-aws
```

The sweeper deletes broadly across the account. `Ctrl+C` requests teardown but
cannot guarantee it after process termination, expired credentials, network
failure, or resources that are still changing. Current cleanup and isolation
limits are described in [Security](../SECURITY.md).

## Results and scoring

Outputs live under `artifacts/experiments/<batch>/`. Each run records
`result.json`, metrics, agent transcripts, API events, an oracle verdict, and
cleanup evidence. `bench report <configuration>` produces `results.csv` and
`summary.md`.

To aggregate configuration-1 results across both trials:

```bash
uv run bench report experiments/paper-config-1.yml
uv run bench report experiments/paper-config-1-t2.yml
uv run summarize-results \
  artifacts/experiments/paper-config-1/results.csv \
  artifacts/experiments/paper-config-1-t2/results.csv \
  --out artifacts/overall.json
```

The summary groups by configured arm while retaining reported model IDs. It
averages trials within cases, then gives each case equal weight. Missing usage
stays missing. All supplied rows count in the pass-rate denominator, including
unscored failures; invalid, partial, and leaked-run counts are reported separately.
Duplicate arm/case/trial rows are rejected.

An oracle `pass` is the task score. Cleanup status is separate: a leak does not
change an already scored verdict. Review the ledger and transcript audit for
contamination or infrastructure failures before making scientific comparisons.
Missing or unstarted cells are not invented; compare `bench status` with the
expected cell count.

Historical results and figure scripts are not included. Historical figures used
figure-specific populations and reviewed run decisions, so aggregating fresh
runs does not recreate those omitted tables. See [reproducibility scope](benchmark.md#reproducibility-scope).

## Time and cost

Offline checks incur no AWS or model charges. Allow roughly **5–15 minutes** for
one live smoke trial, plus initial installation and provider downloads. Its agent
budget is 10 minutes; setup and teardown take additional time. The frozen research
arms allow 30 minutes for the agent, which is not a whole-run deadline.

For context, historical configuration-1 runs across two trials recorded:

| Measurement | Observation |
| --- | --- |
| Runs | 3,060 |
| Whole-run time | Median 3.2 minutes; 90th percentile 7.9 minutes; mean 4.3 minutes |
| Serial account time | Approximately 219 hours |
| Model list-price estimate | Mean $0.33; median $0.20; 90th percentile $0.77 per run |
| Total model estimate | Approximately $1,020 across 3,058 measured runs |

These September 2026 observations are estimates, not quotes or spending caps.
Configuration 2, retries, provider pricing, model access, and caching can change
costs. `harness/pricing.py` records dated list-price estimates; subscriptions may
be billed differently. No complete AWS billing measurement is included.

AWS and the execution host cost extra. EC2/EBS, RDS, public IPv4, Route 53,
Lightsail, storage, requests, and retained resources can incur charges. Consult
[AWS pricing](https://aws.amazon.com/pricing/) and your provider's pricing before
scaling. Configure billing alerts and verify cleanup after interruptions.

## Authentication and rate limits

Claude normally uses its CLI login. An optional paid API fallback uses
`CLOUDGYM_CLAUDE_FALLBACK=anthropic-api` and `CLOUDGYM_ANTHROPIC_API_KEY` in the
launch environment. `--force-route api` selects that fallback immediately.
Use credentials dedicated to this benchmark and keep them out of YAML and Git.
Codex uses its CLI's configured login and waits when its usage limit is exhausted.
