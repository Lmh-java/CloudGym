"""Aggregate fresh bench-report CSVs by configured arm, retaining diagnostic counts.

Trials are averaged within cases, then cases equally. Missing resource usage is
omitted, never zero-filled. A scored pass remains a pass when cleanup leaked.
Reported model IDs are retained while an arm remains the unit of comparison.
"""
from __future__ import annotations

import argparse
import csv
import json
import math
from collections import defaultdict
from pathlib import Path
from statistics import mean

METRICS = ('cost_usd', 'duration_s', 'num_turns', 'tool_calls', 'input_tokens', 'output_tokens')
GROUP = ('arm', 'agent', 'awareness', 'modality', 'distractors')


def aggregate(rows: list[dict[str, str]]) -> list[dict]:
    groups = defaultdict(list)
    seen = set()
    for row in rows:
        if not all(row.get(k) for k in ('arm', 'case', 'trial')):
            raise ValueError('expected bench-report rows with arm, case, and trial')
        identity = (row['arm'], row['case'], row['trial'])
        if identity in seen:
            raise ValueError(f'duplicate arm/case/trial: {identity}; select one attempt per cell')
        seen.add(identity)
        groups[tuple(row.get(k, '') for k in GROUP)].append(row)
    result = []
    for key, runs in sorted(groups.items()):
        cases = defaultdict(list)
        for r in runs:
            cases[r['case']].append(r)
        record = dict(zip(GROUP, key))
        record.update(cases=len(cases), runs=len(runs),
                      scored_runs=sum(r.get('verdict') in {'pass', 'fail'} for r in runs),
                      passed_runs=sum(r.get('verdict') == 'pass' for r in runs),
                      invalid_runs=sum(r.get('validity') == 'invalid' for r in runs),
                      partial_runs=sum(r.get('validity') == 'partial' for r in runs),
                      runs_with_leaks=sum(float(r.get('leaked') or 0) > 0 for r in runs),
                      reported_models=sorted({r['model'] for r in runs if r.get('model')}),
                      trials_per_case={c: len(rs) for c, rs in sorted(cases.items())},
                      # Unscored attempts count as nonpasses here, and remain visible above.
                      pass_rate=mean(mean(r.get('verdict') == 'pass' for r in rs) for rs in cases.values()))
        for metric in METRICS:
            case_means = []
            measured = 0
            for rs in cases.values():
                values = [float(r[metric]) for r in rs if r.get(metric) not in (None, '')]
                if any(not math.isfinite(v) or v < 0 for v in values):
                    raise ValueError(f'{metric}: expected finite nonnegative values')
                measured += len(values)
                if values:
                    case_means.append(mean(values))
            record[metric] = {'mean': mean(case_means) if case_means else None,
                              'measured_runs': measured, 'measured_cases': len(case_means)}
        result.append(record)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('reports', nargs='+', type=Path)
    parser.add_argument('--out', type=Path, help='write JSON here instead of stdout')
    args = parser.parse_args(argv)
    rows = []
    for report in args.reports:
        with report.open(newline='') as stream:
            rows.extend(csv.DictReader(stream))
    try:
        summaries = aggregate(rows)
    except ValueError as exc:
        parser.error(str(exc))
    output = json.dumps({'definitions': {
        'population': 'all supplied rows; no case-category or cleanup-leak exclusions',
        'pass_rate': 'average within cases, then equally across cases; unscored rows count as nonpasses',
        'resources': 'available trials within cases, then equally across measured cases; missing values stay missing',
        'duration_s': 'agent execution time, excluding harness setup and teardown',
        'model': 'group by configured arm; reported model IDs retained',
    }, 'arms': summaries}, indent=2) + '\n'
    if args.out:
        args.out.write_text(output)
    else:
        print(output, end='')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
