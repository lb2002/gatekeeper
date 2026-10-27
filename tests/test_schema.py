from gatekeeper.schema import Verdict, verdict_json_schema


def test_schema_is_strict_everywhere():
    schema = verdict_json_schema()

    def check(node):
        if isinstance(node, dict):
            if node.get("type") == "object" and "properties" in node:
                assert node["additionalProperties"] is False
                assert set(node["required"]) == set(node["properties"])
            for value in node.values():
                check(value)
        elif isinstance(node, list):
            for item in node:
                check(item)

    check(schema)


def test_roundtrip():
    v = Verdict.model_validate(
        {
            "verdict": "malicious",
            "confidence": 0.9,
            "category": "credential_theft",
            "trigger": "install_script",
            "evidence": [{"excerpt_id": "E1", "line_start": 3, "line_end": 5, "why": "reads ~/.npmrc and posts it"}],
            "iocs": [{"type": "url", "value": "http://example.invalid/collect"}],
            "injection_attempt_observed": False,
            "summary": "Postinstall script exfiltrates npm credentials.",
        }
    )
    assert v.verdict.value == "malicious"
