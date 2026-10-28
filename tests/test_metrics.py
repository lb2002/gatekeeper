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


def test_pr_auc_ignores_input_order_of_ties():
    from gatekeeper.eval.metrics import pr_auc

    scores, labels = [0.0, 0.0, 0.0, 0.0, 1.0], [0, 0, 1, 1, 1]
    flipped = list(zip(*sorted(zip(scores, labels), key=lambda t: -t[1])))
    assert pr_auc(scores, labels) == pr_auc(list(flipped[0]), list(flipped[1]))
    assert abs(pr_auc(scores, labels) - (1 / 3 * 1.0 + 2 / 3 * 3 / 5)) < 1e-9
