from nigerian_secrets.benchmark import load_cases, native_detected_ids, run


def test_benchmark_corpus_is_balanced_and_reproducible():
    cases = load_cases()
    positives = sum(case.expected for case in cases)
    negatives = len(cases) - positives
    assert len(cases) >= 500
    assert positives == 360
    assert negatives == 300
    first = run("native", cases)
    second = run("native", cases)
    assert (first.true_positive, first.false_positive, first.true_negative, first.false_negative, first.precision, first.recall, first.f1) == (
        second.true_positive,
        second.false_positive,
        second.true_negative,
        second.false_negative,
        second.precision,
        second.recall,
        second.f1,
    )
    detected = native_detected_ids(cases)
    missing = sorted(case.id for case in cases if case.expected and case.id not in detected)
    assert not missing, f"native detector missed benchmark cases: {missing}"
    assert first.recall >= 0.95
    assert first.precision >= 0.90
