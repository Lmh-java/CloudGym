import pytest
from scripts.summarize_results import aggregate


def row(case, trial, verdict, cost='', **extra):
    return dict(arm='system-consult', case=case, trial=str(trial), verdict=verdict,
                cost_usd=cost, model='model-a', **extra)


def test_case_weighting_missing_usage_and_model_switching():
    rows = [row('a', 1, 'pass', '1'), row('a', 2, 'fail', '3'),
            row('b', 1, 'pass', '', leaked='1')]
    rows[-1]['model'] = 'model-b'
    result, = aggregate(rows)
    assert result['pass_rate'] == .75
    assert result['cost_usd'] == dict(mean=2, measured_runs=2, measured_cases=1)
    assert result['reported_models'] == ['model-a', 'model-b']
    assert result['runs_with_leaks'] == 1
    assert result['passed_runs'] == 2
    assert result['num_turns']['mean'] is None


def test_failed_attempt_stays_in_denominator_and_diagnostics():
    result, = aggregate([row('a', 1, 'pass'), row('a', 2, '', validity='invalid')])
    assert result['pass_rate'] == .5
    assert result['scored_runs'] == 1
    assert result['invalid_runs'] == 1


def test_duplicate_cell_and_nonfinite_usage_rejected():
    with pytest.raises(ValueError, match='duplicate'):
        aggregate([row('a', 1, 'pass'), row('a', 1, 'fail')])
    with pytest.raises(ValueError, match='finite'):
        aggregate([row('a', 1, 'pass', 'nan')])
