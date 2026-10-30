"""Draw docs/lead-times.svg from the live stats: for each confirmed package, when the monitor flagged it
and when the first public report appeared.

    uv run python scripts/lead_chart.py
"""

import json
import urllib.request
from datetime import datetime, timedelta
from pathlib import Path

STATS = "https://lb2002--gatekeeper-api.us-east.modal.run/stats.json"
OUT = Path(__file__).resolve().parents[1] / "docs" / "lead-times.svg"


def ts(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def main() -> None:
    stats = json.load(urllib.request.urlopen(STATS, timeout=60))
    first: dict[str, dict] = {}
    for c in stats["catches"]:
        if c.get("earliest_public") and (c["name"] not in first or c["flagged_at"] < first[c["name"]]["flagged_at"]):
            first[c["name"]] = c
    rows = sorted(first.values(), key=lambda c: c["flagged_at"])
    t0 = min(ts(c["published_at"] or c["flagged_at"]) for c in rows).replace(minute=0, second=0, microsecond=0)
    t1 = max(ts(c["earliest_public"]) for c in rows) + timedelta(hours=2)
    hours = (t1 - t0).total_seconds() / 3600

    left, right, top, row_h = 250, 110, 70, 34
    width = 1100
    height = top + row_h * len(rows) + 70
    span = width - left - right

    def x(t: datetime) -> float:
        return left + span * (t - t0).total_seconds() / 3600 / hours

    out = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" '
           'font-family="Inter, Segoe UI, Helvetica, Arial, sans-serif">',
           "<title>Gatekeeper flags vs. public reports</title>",
           f'<rect width="{width}" height="{height}" fill="#fbfbf9"/>',
           '<text x="24" y="34" font-size="20" font-weight="700" fill="#1d1d1b">Flagged by Gatekeeper vs. first public report</text>',
           f'<text x="24" y="56" font-size="14" fill="#6b6b66">Confirmed malicious npm packages, {t0:%b %d}-{t1:%b %d} (UTC). '
           'Dot: our flag (committed to the public ledger). Bar end: the report\'s import into OSV / GitHub / npm takedown.</text>']
    day = t0.replace(hour=0) + timedelta(days=1)
    while day < t1:
        out.append(f'<line x1="{x(day):.1f}" y1="{top - 8}" x2="{x(day):.1f}" y2="{height - 50}" stroke="#e3e3dd"/>')
        out.append(f'<text x="{x(day) + 4:.1f}" y="{height - 34}" font-size="12" fill="#8a8a84">{day:%a %b %d}</text>')
        day += timedelta(days=1)
    for i, c in enumerate(rows):
        y = top + i * row_h + row_h / 2
        flag, public = ts(c["flagged_at"]), ts(c["earliest_public"])
        lead_h = (public - flag).total_seconds() / 3600
        label = c["name"] if len(c["name"]) <= 30 else c["name"][:29] + "…"
        out.append(f'<text x="{left - 12}" y="{y + 5:.1f}" font-size="14" text-anchor="end" fill="#1d1d1b">{label}</text>')
        out.append(f'<rect x="{x(flag):.1f}" y="{y - 6:.1f}" width="{max(x(public) - x(flag), 2):.1f}" height="12" rx="3" fill="#f4c7c3"/>')
        out.append(f'<circle cx="{x(flag):.1f}" cy="{y:.1f}" r="6" fill="#b4232c"/>')
        out.append(f'<text x="{x(public) + 8:.1f}" y="{y + 5:.1f}" font-size="13" fill="#55554f">'
                   f'{lead_h:.0f} h ahead</text>' if lead_h >= 1.5 else
                   f'<text x="{x(public) + 8:.1f}" y="{y + 5:.1f}" font-size="13" fill="#55554f">{lead_h * 60:.0f} min ahead</text>')
    leads = sorted((ts(c["earliest_public"]) - ts(c["flagged_at"])).total_seconds() / 3600 for c in rows)
    med = (leads[len(leads) // 2] + leads[(len(leads) - 1) // 2]) / 2
    out.append(f'<text x="24" y="{height - 12}" font-size="13" fill="#6b6b66">{len(rows)} packages, all flagged before the public '
               f'report; median lead {med:.0f} h. Source: {STATS}</text>')
    out.append("</svg>")
    OUT.parent.mkdir(exist_ok=True)
    OUT.write_text("\n".join(out) + "\n", encoding="utf-8")
    print(f"wrote {OUT} ({len(rows)} packages, median lead {med:.1f} h)")


if __name__ == "__main__":
    main()
