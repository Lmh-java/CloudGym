# Benchmark license: CC BY 4.0

CloudGym contributions: Copyright (c) 2026 CloudGym Authors.
Upstream IaC-Eval material remains copyright its respective rights holders.

Except where otherwise noted, the benchmark material in this directory and its
subdirectories is licensed under the Creative Commons Attribution 4.0
International license (SPDX: `CC-BY-4.0`). This includes the manifest, task
descriptions, initial/reference Terraform, distractor programs, resolution
policies, Rego oracles, and fixtures. CloudGym's copyright and similar rights in
its modifications and additions to this material are licensed on the same terms.

The license terms, including the warranty disclaimer and limitation of liability,
are available at:
https://creativecommons.org/licenses/by/4.0/legalcode.en

The cases adapt the [IaC-Eval dataset](https://huggingface.co/datasets/autoiac-project/iac-eval)
by the IaC-Eval contributors, distributed under CC BY 4.0. The upstream project
is https://github.com/autoiac-project/iac-eval.
Each case's `agent/task.json` records the source dataset row.

CloudGym modifies these seeds into benchmark tasks with initial/reference
infrastructure, interference programs, policies, and oracles. Recorded fixture
identifiers have been replaced with synthetic values. These are modified cases, not an
unmodified distribution of IaC-Eval; no upstream endorsement is implied.

Retain the applicable attribution and license notices and identify further
modifications when sharing this material, as required by the license. See also
[THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md).

The repository's root MIT license covers the original software and documentation
outside this directory, except where otherwise noted; it does not replace the
license terms for this benchmark material.
