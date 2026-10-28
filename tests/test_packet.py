from gatekeeper.report.packet import build_packet, consensus

ITEM = {
    "name": "evil-pkg", "version": "1.0.0", "seen_at": "2026-10-28T07:00:00Z", "published_at": "2026-10-28T06:59:00Z",
    "excerpts": [{"excerpt_id": "E2", "path": "setup.js", "first_line": 10, "last_line": 20}],
    "verdicts": {
        "spark": {"verdict": "malicious", "confidence": 0.9, "full": {
            "summary": "posts host data", "evidence": [{"excerpt_id": "E2", "line_start": 12, "line_end": 14, "why": "POST"}],
            "iocs": [{"type": "url", "value": "https://collector.example.invalid/x"}]}},
        "glimmer-local": {"verdict": "benign", "confidence": 0.6, "full": {"summary": "fine", "evidence": [], "iocs": []}},
    },
}
INSPECTION = {"publisher": "someone", "tarball_sha256": "ab" * 32, "still_on_registry": True,
              "files": {"setup.js": {"size": 10, "sha256": "cd" * 32}}, "text": {"setup.js": "line one\nline two"}}


def test_packet_maps_evidence_to_files_and_shows_disagreement():
    md = build_packet(ITEM, INSPECTION)
    assert "`setup.js` lines 12-14" in md
    assert "1 of 2 model verdicts malicious/suspicious" in md
    assert "collector.example.invalid" in md and "   2| line two" in md
    assert consensus({}) == "no model verdict yet"
