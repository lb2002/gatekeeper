from gatekeeper.eval.metrics import at_threshold, bootstrap, pr_auc, recall_at_fpr, verdict_risk


def test_perfect_separation():
    scores = [0.9, 0.8, 0.2, 0.1]
    labels = [1, 1, 0, 0]
    p = recall_at_fpr(scores, labels, 0.0)
    assert p.recall == 1.0 and p.fpr == 0.0
    assert pr_auc(scores, labels) == 1.0


def test_threshold_counts():
    p = at_threshold([0.9, 0.6, 0.6, 0.1], [1, 0, 1, 0], 0.6)
    assert (p.recall, p.fpr, p.precision) == (1.0, 0.5, 2 / 3)


def test_verdict_risk_is_monotone():
    assert verdict_risk("malicious", 0.9) > verdict_risk("suspicious", 0.9) > verdict_risk("benign", 0.1) > verdict_risk("benign", 0.9)
    assert verdict_risk(None, None) == 0.0


def test_bootstrap_brackets_estimate():
    scores = [i / 100 for i in range(100)]
    labels = [1 if i > 60 else 0 for i in range(100)]
    est, lo, hi = bootstrap(scores, labels, pr_auc, n=200)
    assert lo <= est <= hi
