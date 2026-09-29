# Add your first case

This tutorial creates a small variant of the [Lambda example](../README.md#case-in-action),
then shows what to change for a new coordination scenario. Commands run from the
repository root after [development setup](../CONTRIBUTING.md#development-setup).
Install OPA 1.x for oracle checks. The offline steps need no AWS or model access.

## 1. Copy a working case

Use a new directory name ending in a three-digit suffix (`<slug>-NNN`), as required
by the validator. The copy command assumes the destination does not already exist:

```bash
cp -R cases/aws/iac-eval-149-iam-role-001 cases/aws/lambda-ownership-demo-001
```

Keep the copied `seed_id` and IaC-Eval provenance: this variant still derives from
row 149. Record your modifications in the pull request and retain
[attribution](../cases/LICENSE.md). A wholly original case should state its actual
origin rather than reuse an unrelated dataset row.

Each case connects five parts:

| File | What you author |
| --- | --- |
| `initial.tf` | The starting infrastructure, where the task is not yet fulfilled. |
| `agent/task.json` | The agent's `utterance`, the main participant's role and intent, and provenance. |
| `agent/resolution_prompt.txt` | Rules that determine which requirements take precedence. |
| `evaluator/distractors/<id>/distractor.py` | A participant's trigger, cloud operations, and consultation reply. |
| `evaluator/oracle.rego` | Properties that make the final outcome correct. |

`expected.tf` is a reference used to discover observed resource types, not a
deployment the agent must reproduce. Put files the agent actually needs under
`agent/files/`; keep reference answers and evaluator logic outside that directory.

## 2. Make one consistent change

For this exercise, change the sibling workload's marking from `orders-api` to
`billing-api` throughout these four files in your copy:

- `evaluator/distractors/namesake-function-claim/distractor.py`
- `evaluator/oracle.rego`
- `evaluator/oracle-tests.json`
- `evaluator/consult-tests.json`

Update all occurrences, including fixture descriptions, identifiers, and questions.
The distractor must write the new marking and return it in its `fingerprint`;
the oracle must require it; the fixtures must exercise it. The task and resolution
policy stay the same because the ownership rule has not changed. This is an
authoring exercise, not a new benchmark challenge by itself.

For a new scenario, define the task, concurrent intent, and resolution together.
Choose the coordination problem you want to exercise:

- **Semantic conflict (`SC`):** requirements cannot both hold; a policy decides precedence.
- **Intent ambiguity (`IA`):** new state creates multiple plausible targets or values.
- **Execution conflict (`EC`):** compatible changes temporarily block one another.

State the resolution as a rule about the outcome, without revealing hidden
resource values or prescribing an API sequence. The current validator expects
at most two nonempty policy lines and fewer than 50 words.

## 3. Connect triggers and consultation

Read the copied
[name-claim distractor](../cases/aws/iac-eval-149-iam-role-001/evaluator/distractors/namesake-function-claim/distractor.py)
as a complete implementation. Each module declares exactly one `@distract`
function and runs its AWS operations inside `run()`, not at import time.

- A `predicate(snapshot)` fires on observed state; normally it should be false at
  the initial state and tolerate missing resources.
- `api=on_api(...)` fires around a matching request. The example uses
  `phase="before"` and `release="after_completed"` to claim the name before the
  agent's creation request continues. Other tasks may need `after_success`.
- `resolution` gives the participant's policy reply. Return observable values
  introduced by the change as `{"fingerprint": [...]}` from `run()`.
- Under `awareness: consult`, the agent must read and cite a fingerprint after
  the change lands to reach its participant. Test both matching questions and
  questions that should reach nobody in `consult-tests.json`.

Use bounded waits for AWS operations and make retries safe. If you introduce a
resource type, check [extractor coverage](../harness/extractor/aws/capabilities),
the [sandbox policy](../infra/aws/sandbox-scp.json), and cleanup support. Declare
additional observed Terraform types in `task.json`'s `resource_types` if neither
Terraform file contains them. See the
[decorators](../harness/runtime/decorators.py) for the supported trigger options.

## 4. Test what the oracle accepts and rejects

The oracle uses `package cloudgym`, `import rego.v1`, and the query
`data.cloudgym.verdict`, returning `"pass"` or `"fail"`. Its inputs are
`s0`, `s_final`, `distractors`, and `invariants`.

Check semantic properties rather than exact snapshots or a required sequence of
actions. Gate a participant's requirement on
`input.distractors["<id>"].status == "succeeded"`. If its change must instead be
overridden by the main task, document that explicitly, as the example does for
the release handler. Use names, tags, and initial-state relationships rather
than hard-coded account IDs or generated resource IDs.

Update `oracle-tests.json` with positive and negative fixtures:

| Situation | Expected verdict |
| --- | --- |
| Nothing changed | `fail` |
| Main task completed, no interference | `pass` |
| Main task and all applicable policy requirements satisfied | `pass` |
| A required property is broken, or a succeeded participant's protected change is lost | `fail` |
| A failed participant's change is absent, but the task is otherwise correct | `pass` |
| Prompt followed without discovering required state, with all distractors succeeded (`prompt-only`) | `fail` |

The validator also expects at least six negative control fixtures that break the
main intent without interference. Keep the copied fixtures and adapt them to your
scenario; include a distinct failure for each important success condition.
For requirements that must hold throughout execution, add an
`evaluator/invariants/<id>/invariant.py` with `@invariant` and check its violation
history in the oracle. A final snapshot alone cannot establish those properties.

## 5. Validate offline

```bash
uv run validate-case cases/aws/lambda-ownership-demo-001
uv run pytest tests/cases/test_oracles.py -q -k lambda-ownership-demo-001
```

The validator checks layout, metadata, triggers, consultation fixtures, and oracle
fixtures. It imports case modules, so run it only on trusted code. Resolve failures
and review warnings; the validator predates some cases and is not live certification.
Check for skipped checks or missing dependencies, even if the final label is `VALID`.

## 6. Preview and verify the variant

Save this as `experiments/lambda-ownership-demo-001.yml`:

```yaml
batch: lambda-ownership-demo-001
defaults:
  agent: claude
  timeout: 600
  poll_interval: 10
  trials: 1
  modality: hybrid
cases:
  - ../cases/aws/lambda-ownership-demo-001
arms:
  - {name: control, distractors: false, awareness: none}
  - {name: policy, distractors: true, awareness: none}
  - {name: consult, distractors: true, awareness: consult}
```

```bash
uv run bench run experiments/lambda-ownership-demo-001.yml --dry-run
```

Expect three cells: control, policy supplied in the prompt, and policy discovered
through consultation. This explicit case path works without a manifest entry.

After [AWS setup](../infra/aws/README.md), use a disposable Linux host and sandbox
account for live checks. These commands incur charges:

```bash
uv run bench run experiments/lambda-ownership-demo-001.yml --allow-aws --slots 1 --allow-dirty
uv run bench report experiments/lambda-ownership-demo-001.yml
uv run bench pool
```

For development, `--allow-dirty` permits the edits you just made. Pin a clean
commit and an explicit model for reproducible comparisons. Inspect trigger
outcomes, consultation records, oracle verdicts, and cleanup evidence. Establish
that a correct solution is possible and that each intended interference actually
lands; an agent failure alone does not establish case quality.

## 7. Prepare a contribution

For a genuinely new case ready for inclusion, add its directory name, `status`,
and category to [cases/manifest.json](../cases/manifest.json), following existing
entries, and update benchmark counts. The manifest is an inventory: `cases_from`
discovers directories using `task.json`'s `lifecycle.status` (absent means active),
so an unlisted copy can still enter a batch using directory discovery.

Keep tutorial copies out of published comparisons. Submit the new case, fixtures,
and a concise account of validation, provenance, and any remaining limitations.
Keep frozen experiment configurations stable and review
[contribution guidance](../CONTRIBUTING.md#pull-requests-and-issue-reports).
