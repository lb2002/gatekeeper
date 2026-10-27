"""`gk` command line interface."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import typer
from rich.console import Console
from rich.table import Table

from gatekeeper.npm import feed, packument
from gatekeeper.popular import load_popular
from gatekeeper.triage.meta import score_metadata

app = typer.Typer(no_args_is_help=True, help="Gatekeeper: static malware detection for npm.")
console = Console()


@app.callback()
def main() -> None:
    """Gatekeeper command line."""


@app.command("poll-once")
def poll_once(
    changes: int = typer.Option(2000, help="How many recent registry changes to look at."),
    window_minutes: int = typer.Option(60, help="Only score versions published within this window."),
    top: int = typer.Option(25, help="How many of the highest-scoring versions to show."),
    workers: int = typer.Option(16, help="Parallel packument fetches."),
) -> None:
    """Score the most recent npm releases from metadata only (no archives are downloaded)."""
    popular = load_popular()
    with feed.make_client() as client:
        head = feed.current_seq(client)
        since = max(0, head - changes)
        names: dict[str, None] = {}
        while since < head and len(names) < changes:
            batch, since_next = feed.fetch_changes(client, since, limit=1000)
            if not batch or since_next <= since:
                break
            for ch in batch:
                if not ch.deleted:
                    names.setdefault(ch.name)
            since = since_next
        console.print(f"feed head {head}, {len(names)} changed packages")

        def score(name: str):
            try:
                doc = packument.fetch_packument(client, name)
            except Exception as exc:  # network hiccups should not stop the batch
                return [("error", name, str(exc))]
            if not doc:
                return []
            out = []
            for info in packument.recent_versions(doc, timedelta(minutes=window_minutes)):
                if info.is_security_holder:
                    continue
                out.append(("ok", info, score_metadata(info, popular)))
            return out

        with ThreadPoolExecutor(max_workers=workers) as pool:
            results = [r for rs in pool.map(score, names) for r in rs]

    scored = [(info, s) for kind, info, s in results if kind == "ok"]
    errors = sum(1 for kind, *_ in results if kind == "error")
    scored.sort(key=lambda item: item[1].score, reverse=True)
    table = Table(title=f"{len(scored)} versions published in the last {window_minutes} min ({errors} fetch errors)")
    table.add_column("score", justify="right")
    table.add_column("package")
    table.add_column("reasons")
    for info, s in scored[:top]:
        table.add_row(str(s.score), f"{info.name}@{info.version}", "; ".join(s.reasons))
    console.print(table)
    flagged = sum(1 for _, s in scored if s.score >= 3)
    console.print(f"score >= 3 (would go to archive scan): {flagged} of {len(scored)}")


if __name__ == "__main__":
    app()
