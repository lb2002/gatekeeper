"""Verdict schema shared by every model backend (Muse Spark, Muse Glimmer) and by the evaluation.

The JSON schema exported here is used for strict structured output, so every field is required
and no extra properties are allowed.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class VerdictLabel(str, Enum):
    malicious = "malicious"
    suspicious = "suspicious"
    benign = "benign"


class Category(str, Enum):
    credential_theft = "credential_theft"
    exfiltration = "exfiltration"
    remote_payload = "remote_payload"
    backdoor = "backdoor"
    miner = "miner"
    destructive = "destructive"
    dep_confusion_probe = "dep_confusion_probe"
    typosquat_only = "typosquat_only"
    protestware = "protestware"
    spam = "spam"
    none = "none"
    other = "other"


class Trigger(str, Enum):
    install_script = "install_script"
    on_require = "on_require"
    bin = "bin"
    build_hook = "build_hook"
    unknown = "unknown"
    none = "none"


class IocType(str, Enum):
    url = "url"
    domain = "domain"
    ip = "ip"
    webhook = "webhook"
    path = "path"
    env_var = "env_var"
    other = "other"


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Evidence(_Strict):
    excerpt_id: str = Field(description="ID of the excerpt in the evidence bundle, e.g. 'E3'.")
    line_start: int = Field(description="First cited line number within that excerpt.")
    line_end: int = Field(description="Last cited line number within that excerpt.")
    why: str = Field(description="Why these lines matter, at most 160 characters.")


class Ioc(_Strict):
    type: IocType
    value: str


class Verdict(_Strict):
    verdict: VerdictLabel
    confidence: float = Field(description="Confidence in the verdict, 0.0 to 1.0.")
    category: Category
    trigger: Trigger
    evidence: list[Evidence]
    iocs: list[Ioc]
    injection_attempt_observed: bool = Field(
        description="True if the package data contains text addressed to an AI reviewer or other instructions."
    )
    summary: str = Field(description="One or two sentences, at most 300 characters.")


STRING_CAPS = {"summary": 300, "why": 160}


def verdict_json_schema() -> dict:
    """Strict JSON schema for structured output: all properties required, no additional properties."""
    schema = Verdict.model_json_schema()

    def tighten(node: object) -> None:
        if isinstance(node, dict):
            if node.get("type") == "object" and "properties" in node:
                node["required"] = list(node["properties"].keys())
                node["additionalProperties"] = False
                # Length caps are enforced by constrained decoding: without them Spark Open sometimes
                # loops inside a free-text field until max_tokens and the JSON never closes (35% of
                # its test-set answers were lost that way).
                for key, prop in node["properties"].items():
                    if prop.get("type") == "string" and "enum" not in prop:
                        prop["maxLength"] = STRING_CAPS.get(key, 200)
                    elif prop.get("type") == "array":
                        prop["maxItems"] = 8
            for value in node.values():
                tighten(value)
        elif isinstance(node, list):
            for item in node:
                tighten(item)

    tighten(schema)
    return schema
