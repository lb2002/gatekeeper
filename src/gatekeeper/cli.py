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


@app.command("check")
def check(
    target: str = typer.Argument(..., help="A package spec 'name' or 'name@version', or a local .tgz file."),
    backend: str = typer.Option("local", help="'local' (Muse Glimmer via llama-server) or 'spark' (Meta API)."),
    show_bundle: bool = typer.Option(False, help="Print the evidence bundle sent to the model."),
) -> None:
    """Statically check one package: rules first, then a Meta model. Nothing is executed."""
    from pathlib import Path

    from gatekeeper.evidence.bundle import build_bundle
    from gatekeeper.models.backends import classify_local, classify_spark
    from gatekeeper.npm.tarball import read_tarball
    from gatekeeper.triage.content import score_content

    meta_reasons: list[str] = []
    if target.endswith(".tgz") and Path(target).exists():
        data = Path(target).read_bytes()
        name, version = Path(target).stem, "local"
    else:
        name, _, version = target.rpartition("@") if target.rfind("@") > 0 else (target, "", "")
        with feed.make_client() as client:
            doc = packument.fetch_packument(client, name)
            if not doc:
                raise typer.BadParameter(f"package {name} not found")
            version = version or (doc.get("dist-tags") or {}).get("latest", "")
            info = packument.version_info(doc, version)
            meta_reasons = score_metadata(info, load_popular()).reasons
            resp = client.get(info.tarball_url)
            resp.raise_for_status()
            data = resp.content
    pkg = read_tarball(data)
    content = score_content(pkg)
    bundle = build_bundle(name, version, pkg, content, meta_reasons=meta_reasons)
    console.print(f"[bold]{name}@{version}[/]  rules score {content.score}  ({', '.join(sorted(content.rules)) or 'no rule hits'})")
    if show_bundle:
        console.print(bundle.render(), markup=False, highlight=False)
    result = classify_spark(bundle) if backend == "spark" else classify_local(bundle)
    v = result.verdict
    if v is None:
        console.print(f"[red]model output unusable[/]: {result.errors}")
        raise typer.Exit(2)
    color = {"malicious": "red", "suspicious": "yellow", "benign": "green"}[v.verdict.value]
    console.print(
        f"[{color} bold]{v.verdict.value.upper()}[/] ({v.confidence:.2f}) category={v.category.value} trigger={v.trigger.value}  "
        f"\\[{result.backend}, {result.latency_s:.1f}s, {result.output_tokens} output tokens]"
    )
    console.print(v.summary, markup=False)
    for ev in v.evidence:
        console.print(f"  {ev.excerpt_id} lines {ev.line_start}-{ev.line_end}: {ev.why}", markup=False)
    if v.injection_attempt_observed:
        console.print("[magenta]prompt-injection attempt observed in package data[/]")
    if result.errors:
        console.print(f"[yellow]validation issues:[/] {result.errors}")


@app.command("worker")
def worker(
    max_items: int = typer.Option(0, help="Stop after this many items (0 = run forever)."),
    status_only: bool = typer.Option(False, "--status", help="Only print monitor and queue status."),
) -> None:
    """Classify flagged packages from the live monitor with the local Muse Glimmer (llama-server on :8080)."""
    import os

    from gatekeeper.worker.laptop import MonitorApi, load_env, run

    load_env()
    api = MonitorApi(os.environ["GK_API_URL"], os.environ["GK_WORKER_TOKEN"])
    if status_only:
        console.print(api.status())
        return

    def show(item: dict, result) -> None:
        v = result.verdict
        label = v.verdict.value.upper() if v else "NO VERDICT"
        console.print(
            f"{item['key']}  priority={item['priority']}  ->  {label}"
            + (f" ({v.confidence:.2f}, {v.category.value})" if v else f" {result.errors[:1]}")
            + f"  {result.latency_s:.0f}s",
            markup=False,
        )

    done = run(api, max_items=max_items or None, on_result=show)
    console.print(f"processed {done} item(s)")


@app.command("review")
def review(
    limit: int = typer.Option(10, help="How many items to go through."),
    include_unjudged: bool = typer.Option(False, help="Also show items no model has judged yet."),
    reports_dir: str = typer.Option("data/reports", help="Where report drafts are written."),
) -> None:
    """Go through flagged packages (model verdict malicious/suspicious first) and record your decision."""
    import os

    from rich.panel import Panel

    from gatekeeper.report.drafts import write_drafts
    from gatekeeper.worker.laptop import MonitorApi, load_env

    load_env()
    api = MonitorApi(os.environ["GK_API_URL"], os.environ["GK_WORKER_TOKEN"])
    rank = {"malicious": 0, "suspicious": 1, "benign": 3, None: 2}

    def worst(row: dict) -> str | None:
        labels = [v.get("verdict") for v in (row.get("verdicts") or {}).values()]
        return min(labels, key=lambda lab: rank.get(lab, 2)) if labels else None

    rows = [r for r in api.items(limit=500) if not r.get("review")]
    if not include_unjudged:
        rows = [r for r in rows if worst(r) in ("malicious", "suspicious")]
    rows.sort(key=lambda r: (rank.get(worst(r), 2), -r["priority"]))
    if not rows:
        console.print("nothing to review right now")
        return
    for row in rows[:limit]:
        it = api.item(row["key"])
        console.rule(f"{row['key']}  priority {row['priority']}  published {row.get('published_at')}")
        console.print(Panel(it["bundle"], title="evidence bundle", expand=False), markup=False, highlight=False)
        for backend, v in (row.get("verdicts") or {}).items():
            console.print(f"{backend}: {v.get('verdict')} ({v.get('confidence')})  {v.get('errors') or ''}", markup=False)
        if row.get("confirmation"):
            console.print(f"public sources: {row['confirmation']}", markup=False)
        console.print(f"npm page: https://www.npmjs.com/package/{row['key'].rsplit('@', 1)[0]}", markup=False)
        choice = typer.prompt("[m]alicious / [b]enign / [u]nsure / [s]kip / [q]uit", default="s").strip().lower()[:1]
        if choice == "q":
            break
        if choice not in ("m", "b", "u"):
            continue
        decision = {"m": "malicious", "b": "benign", "u": "unsure"}[choice]
        note = typer.prompt("note (optional)", default="", show_default=False)
        api.review(row["key"], decision, note)
        if decision == "malicious":
            judged = [v for v in (row.get("verdicts") or {}).values() if v.get("full")]
            judged.sort(key=lambda v: (rank.get(v.get("verdict"), 2), -(v.get("confidence") or 0)))
            full = judged[0]["full"] if judged else {}
            files = write_drafts({"name": it["name"], "version": it["version"]}, full, reports_dir, note)
            console.print(f"[red]recorded as malicious[/]; report drafts: {files[0].rsplit(os.sep, 1)[0]}")
            console.print("Submit: npm 'Report malware' button on the package page (npm_report.txt), and a PR to ossf/malicious-packages (osv.json at the path in osv_path.txt).")
        else:
            console.print(f"recorded as {decision}")


if __name__ == "__main__":
    app()
