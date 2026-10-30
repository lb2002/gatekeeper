from gatekeeper.report.chart import render


def test_package_names_are_escaped_in_the_svg():
    stats = {"catches": [{"name": "<script>alert(1)</script>", "version": "1.0.0", "published_at": "2026-10-28T10:00:00Z",
                          "flagged_at": "2026-10-28T10:01:00Z", "earliest_public": "2026-10-29T10:00:00Z"}]}
    svg = render(stats, source="https://x/?a=<b>")
    assert "<script>" not in svg and "&lt;script&gt;" in svg and "&lt;b&gt;" in svg


def test_no_catches_yet():
    assert "no confirmed detections" in render({"catches": []})
