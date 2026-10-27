"""Check that a model verdict only cites evidence that exists in the bundle it was shown."""

from __future__ import annotations

from gatekeeper.evidence.bundle import Bundle
from gatekeeper.schema import Verdict


def citation_errors(verdict: Verdict, bundle: Bundle) -> list[str]:
    errors: list[str] = []
    for ev in verdict.evidence:
        ex = bundle.excerpt(ev.excerpt_id)
        if ex is None:
            errors.append(f"{ev.excerpt_id}: no such excerpt")
            continue
        if ev.line_start > ev.line_end:
            errors.append(f"{ev.excerpt_id}: line_start {ev.line_start} > line_end {ev.line_end}")
        if ev.line_start < ex.first_line or ev.line_end > ex.last_line:
            errors.append(
                f"{ev.excerpt_id}: lines {ev.line_start}-{ev.line_end} outside {ex.first_line}-{ex.last_line}"
            )
    if verdict.verdict.value != "benign" and not verdict.evidence:
        errors.append("non-benign verdict without evidence")
    if verdict.verdict.value == "malicious" and verdict.evidence:
        code_refs = [ev for ev in verdict.evidence if not _is_manifest(bundle, ev.excerpt_id)]
        if not code_refs:
            errors.append("weak evidence: malicious verdict cites only package.json")
    return errors


def _is_manifest(bundle, excerpt_id: str) -> bool:
    for ex in getattr(bundle, "excerpts", None) or []:
        if getattr(ex, "excerpt_id", None) == excerpt_id:
            return str(getattr(ex, "path", "")).startswith("package.json")
    refs = getattr(bundle, "refs", None) or []
    return any(r.excerpt_id == excerpt_id and getattr(r, "path", "").startswith("package.json") for r in refs)
