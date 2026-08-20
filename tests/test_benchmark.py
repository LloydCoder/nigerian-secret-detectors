from nigerian_secrets.benchmark import load_cases, run


def test_benchmark_corpus_is_balanced_and_reproducible():
    cases = load_cases()
    positives = sum(case.expected for case in cases)
    negatives = len(cases) - positives
    assert positives >= 15
    assert negatives >= 10
    first = run("native", cases)
    second = run("native", cases)
    assert first == second
    assert first.recall >= 0.95
    assert first.precision >= 0.90
