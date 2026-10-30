"""Draw docs/lead-times.svg from the live stats: for each confirmed package, when the monitor flagged it
and when the first public report appeared. The live page serves the same chart at /lead-times.svg.

    uv run python scripts/lead_chart.py
"""

import json
import urllib.request
from pathlib import Path

from gatekeeper.report.chart import render

STATS = "https://lb2002--gatekeeper-api.us-east.modal.run/stats.json"
OUT = Path(__file__).resolve().parents[1] / "docs" / "lead-times.svg"


def main() -> None:
    stats = json.load(urllib.request.urlopen(STATS, timeout=60))
    OUT.parent.mkdir(exist_ok=True)
    OUT.write_text(render(stats, source=STATS), encoding="utf-8")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
