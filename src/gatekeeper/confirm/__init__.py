"""Check whether independent public sources later confirmed a flagged npm version as malicious."""

from __future__ import annotations

import re
from datetime import datetime, timezone

_FRACTION = re.compile(r"\.(\d+)")


def parse_ts(value: str | None) -> datetime | None:
    """Parse an RFC3339 timestamp (any fraction length, 'Z' or offset) into an aware UTC datetime."""
    if not value or not isinstance(value, str):
        return None
    text = _FRACTION.sub(lambda m: "." + m.group(1)[:6].ljust(6, "0"), value.strip(), count=1)
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00").replace("z", "+00:00"))
    except ValueError:
        return None
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)


def to_iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def earliest(values) -> str | None:
    """Earliest of the given timestamp strings, normalised to ISO UTC, or None."""
    parsed = [dt for dt in map(parse_ts, values) if dt is not None]
    return to_iso(min(parsed)) if parsed else None


# Imported last: the source modules import the helpers above from this package.
from gatekeeper.confirm.tracker import (  # noqa: E402
    Confirmation,
    check,
    flag_lead_minutes,
    publish_to_flag_minutes,
)

__all__ = [
    "Confirmation",
    "check",
    "earliest",
    "flag_lead_minutes",
    "parse_ts",
    "publish_to_flag_minutes",
    "to_iso",
]
