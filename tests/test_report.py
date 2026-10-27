import json

from gatekeeper.report.drafts import npm_report_text, osv_draft, osv_path, write_drafts

ITEM = {"name": "@evil/axois-retry", "version": "1.0.0"}
VERDICT = {
    "verdict": "malicious",
    "category": "exfiltration",
    "trigger": "install_script",
    "summary": "Postinstall reads ~/.npmrc and posts it to an external host.",
    "evidence": [{"excerpt_id": "E2", "line_start": 6, "line_end": 9, "why": "reads .npmrc and posts it"}],
    "iocs": [{"type": "domain", "value": "collector.example.invalid"}],
}


def test_osv_draft_has_required_fields():
    d = osv_draft(ITEM, VERDICT)
    assert d["affected"][0]["package"] == {"ecosystem": "npm", "name": "@evil/axois-retry"}
    assert d["affected"][0]["versions"] == ["1.0.0"]
    assert "collector.example.invalid" in d["details"]
    assert d["credits"][0]["type"] == "FINDER"
    assert "id" not in d  # assigned by OpenSSF on merge


def test_paths_and_text(tmp_path):
    assert osv_path("@evil/axois-retry") == "osv/malicious/npm/@evil/axois-retry/MAL-0000-evil-axois-retry.json"
    assert "Affected version(s): 1.0.0" in npm_report_text(ITEM, VERDICT)
    files = write_drafts(ITEM, VERDICT, tmp_path)
    assert len(files) == 3
    folder = tmp_path / "@evil__axois-retry@1.0.0"
    assert json.loads((folder / "osv.json").read_text())["summary"].startswith("Malicious code")
