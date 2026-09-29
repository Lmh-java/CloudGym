# Benchmark structure

CloudGym ships 102 active AWS cases in [cases/manifest.json](../cases/manifest.json):
46 labeled `SC`, 38 labeled `IA` (Intent Ambiguity), and 18 labeled `EC`.
Historical `AI` labels refer to `IA`. The included cases are self-contained;
`seed_id` records provenance rather than requiring the original seed checkout.

## Case layout

```text
cases/aws/<case>/
  initial.tf                         Initial infrastructure
  expected.tf                        Reference infrastructure
  agent/
    task.json                        Task, intent, and source provenance
    resolution_prompt.txt            Resolution policy
    files/                           Optional files supplied to the agent
  evaluator/
    oracle.rego                      Scoring rules
    oracle-tests.json                Offline scoring fixtures
    consult-tests.json               Consultation fixtures, where present
    distractors/<id>/distractor.py    Triggered infrastructure changes
    invariants/<id>/invariant.py      Optional checks across observations
```

The runtime deploys `initial.tf`, provides the task and experiment-specific policy
or tool surface to the agent, and triggers distractors as the agent interacts
with AWS. The oracle evaluates the resulting state. Invariant histories can
capture transient violations that a final snapshot alone would miss.

Reference answers and evaluator programs belong outside the agent workspace.
Filesystem confinement and transcript audits help enforce that boundary, but
are subject to the [current security limitations](../SECURITY.md).

## Provenance

Cases were generated with LLM assistance from
[IaC-Eval](https://huggingface.co/datasets/autoiac-project/iac-eval) seeds and checked
with programmatic validators, oracle fixtures, and live certification during
benchmark development. Each case's `agent/task.json` retains its source row.
Recorded fixture account identifiers have been replaced with synthetic values;
fixtures are test inputs, not credentials.

Opus 5 was used for case generation and certification; the frozen research
configurations evaluate an Opus 5.5 arm. Generation and evaluation model identities
are distinct parts of the experiment record.

## Reproducibility scope

This repository includes the runtime, evaluation harness, frozen cases, prompts,
policies, oracle fixtures, and experiment configurations for running new experiments.
The case-generation pipeline, historical certification outputs, historical run
results, and figure scripts are not included.

For reproducible comparisons, retain the source commit, exact configuration,
requested and reported model IDs, CLI and infrastructure tool versions, trial
identifiers, and full run records. Document any excluded runs and model
substitutions. Changes to prompts, permissions, isolation, or scoring may change
results and should be evaluated explicitly.

The offline validator predates some cases. Read its findings alongside the oracle
fixtures; a validator finding is not by itself a complete assessment of a case.
See [Contributing](../CONTRIBUTING.md) for validation commands and
[Experiments](experiments.md#results-and-scoring) for aggregation semantics.

## Licensing

Benchmark material under `cases/` is licensed under [CC BY 4.0](../cases/LICENSE.md).
The original software and documentation outside `cases/` use [MIT](../LICENSE),
except where otherwise noted. See [third-party notices](../THIRD_PARTY_NOTICES.md)
for upstream attribution and modifications.
