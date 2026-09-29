# Third-party notices and license scope

CloudGym's original software and documentation outside `cases/` are licensed
under the MIT License in `LICENSE`, except where otherwise noted. Benchmark
material under `cases/` is licensed under CC BY 4.0 as described in
`cases/LICENSE.md`. The MIT license does not replace third-party license terms.

## IaC-Eval-derived benchmark material

The generated cases derive from the IaC-Eval dataset by the IaC-Eval contributors:
https://huggingface.co/datasets/autoiac-project/iac-eval
and https://github.com/autoiac-project/iac-eval.
The source dataset card declares CC BY 4.0:
https://creativecommons.org/licenses/by/4.0/.
Each case's `agent/task.json` retains its dataset row provenance. The cases adapt
those seeds into initial/reference infrastructure, tasks, interference programs,
policies, and oracles. Recorded fixture identifiers have been replaced with synthetic values.
These are modified benchmark cases, not an unmodified distribution of IaC-Eval.

Example public repository URLs and AWS public-image owner identifiers in task
inputs refer to upstream resources.
Dependencies retain their respective licenses and are installed separately.

When redistributing the benchmark material, retain the applicable attribution,
license and disclaimer notices, and identify modifications as required by
CC BY 4.0. Its warranty disclaimer and limitation of liability are in
Section 5 of the [license](https://creativecommons.org/licenses/by/4.0/legalcode.en).
