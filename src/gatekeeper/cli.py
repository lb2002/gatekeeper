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
                if info.is_npm_placeholder:
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
    backend: str = typer.Option("local", help="'local' (Muse Glimmer via llama-server), 'fireworks' or 'baseten' (Muse Spark Open) or 'spark' (Meta API)."),
    show_bundle: bool = typer.Option(False, help="Print the evidence bundle sent to the model."),
) -> None:
    """Statically check one package: rules first, then a Meta model. Nothing is executed."""
    from pathlib import Path

    from gatekeeper.evidence.bundle import build_bundle
    from gatekeeper.models.backends import classify_local, classify_spark, classify_spark_open_baseten, classify_spark_open_fireworks
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
    classify = {"spark": classify_spark, "fireworks": classify_spark_open_fireworks,
                "baseten": classify_spark_open_baseten}.get(backend, classify_local)
    result = classify(bundle)
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


guard_app = typer.Typer(help="Install guard for npm/npx (humans and AI coding agents).")
app.add_typer(guard_app, name="guard")


@guard_app.command("enable")
def guard_enable() -> None:
    """Write npm/npx shims to ~/.gatekeeper/bin (put that directory first on PATH, or use `gk guard shell`)."""
    import shutil
    import sys

    from gatekeeper.guard import shim

    gk_exe = shutil.which("gk") or sys.argv[0]
    cfg = shim.enable(gk_exe)
    console.print(f"shims written to {shim.BIN}", markup=False)
    console.print(f"real npm: {cfg['npm']}", markup=False)
    console.print("Start a guarded shell with: gk guard shell")


@guard_app.command("shell")
def guard_shell() -> None:
    """Open a PowerShell with the guard shims first on PATH (start AI coding agents from here)."""
    import os
    import subprocess

    from gatekeeper.guard import shim

    env = dict(os.environ)
    env["PATH"] = str(shim.BIN) + os.pathsep + env.get("PATH", "")
    env["GK_GUARD"] = "1"
    console.print("[green]Gatekeeper guard active in this shell[/] (exit to leave)")
    subprocess.run(["powershell", "-NoLogo"], env=env)


@guard_app.command("update-model")
def guard_update_model() -> None:
    """Download the local first-stage classifier (plain JSON, ~6 MB) from the Modal volume."""
    import subprocess

    from gatekeeper.guard.core import FAST_MODEL_FILE, load_fast_model

    FAST_MODEL_FILE.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["modal", "volume", "get", "--force", "gatekeeper-data", "models/fastclf.json", str(FAST_MODEL_FILE)], check=True)
    model = load_fast_model()
    console.print(f"local classifier: {len(model.index):,} terms, threshold {model.threshold:.3f}", markup=False)


@guard_app.command("update-osv")
def guard_update_osv(
    from_osv: bool = typer.Option(False, "--from-osv", help="Build the list yourself from OSV's npm/all.zip (~220 MB) "
                                  "instead of downloading the monitor's daily copy (~3 MB)"),
) -> None:
    """Download the list of npm packages OSV reports as malicious, for the guard's offline check."""
    import json
    import tempfile
    from pathlib import Path

    import httpx

    from gatekeeper.confirm.malindex import ALL_ZIP, build_index
    from gatekeeper.guard.core import MAL_INDEX_FILE, MAL_INDEX_URL, load_mal_index

    MAL_INDEX_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = MAL_INDEX_FILE.with_suffix(".tmp")
    if from_osv:
        with tempfile.TemporaryDirectory() as d:
            zpath = Path(d) / "all.zip"
            with httpx.stream("GET", ALL_ZIP, timeout=300, follow_redirects=True) as resp, zpath.open("wb") as fh:
                resp.raise_for_status()
                for chunk in resp.iter_bytes(1 << 20):
                    fh.write(chunk)
            tmp.write_text(json.dumps(build_index(zpath)), encoding="utf-8")
    else:
        resp = httpx.get(MAL_INDEX_URL, timeout=120, follow_redirects=True)
        resp.raise_for_status()
        data = resp.json()  # parse before replacing the old list
        if not isinstance(data, dict) or len(data) < 1000:
            raise typer.Exit(f"unexpected index from {MAL_INDEX_URL}")
        tmp.write_text(json.dumps(data), encoding="utf-8")
    tmp.replace(MAL_INDEX_FILE)
    console.print(f"known malicious npm packages: {len(load_mal_index()):,}", markup=False)


@guard_app.command("run", context_settings={"allow_extra_args": True, "ignore_unknown_options": True})
def guard_run(ctx: typer.Context, tool: str = typer.Argument(..., help="npm or npx")) -> None:
    """Called by the shims: check the packages, then run the real npm/npx with the same arguments."""
    import subprocess

    from rich.panel import Panel

    from gatekeeper.guard import shim
    from gatekeeper.guard.core import ALLOW_FLAG, check_spec, index_age_days, load_fast_model, package_specs

    args = [a for a in ctx.args if a != "--"]
    cfg = shim.config()
    real = shim.npm_command(cfg, tool)
    allow = ALLOW_FLAG in args
    specs = package_specs(tool, args)
    if specs and not allow:
        fast_model = load_fast_model()
        stale = index_age_days()
        if stale is None or stale > 3:
            console.print("[yellow]gatekeeper[/] the offline OSV malware list is "
                          + ("missing" if stale is None else f"{stale:.0f} days old") + "; run `gk guard update-osv`", highlight=False)
        for spec in specs:
            console.print(f"[cyan]gatekeeper[/] checking {spec} ...", highlight=False)
            try:
                d = check_spec(shim.npm_command(cfg, "npm"), spec, fast_model=fast_model)
            except Exception as exc:
                # Fail closed: a package must not get through just because checking it failed
                # (an attacker could craft an archive that makes the check error out).
                console.print(f"[red]gatekeeper could not check {spec}: {exc}; blocked[/]", highlight=False)
                console.print(f"If you are sure the package is safe, re-run with {ALLOW_FLAG}.", markup=False)
                typer.echo("Gatekeeper could not verify this package, so nothing was installed. Do not retry with other flags; ask the user.", err=True)
                raise typer.Exit(1)
            if d.allowed:
                console.print(f"[green]allowed[/] {d.name}@{d.version}: {d.reason} ({d.seconds:.1f}s)", highlight=False)
                continue
            lines = [f"{d.reason}", ""]
            for ev in (d.verdict or {}).get("evidence", []):
                lines.append(f"{ev['excerpt_id']} lines {ev['line_start']}-{ev['line_end']}: {ev['why']}")
            iocs = [i["value"] for i in (d.verdict or {}).get("iocs", [])]
            if iocs:
                lines.append("indicators: " + ", ".join(iocs))
            if (d.verdict or {}).get("injection_attempt_observed"):
                lines.append("the package contains text trying to talk the AI reviewer out of blocking it")
            if d.kind == "too_new":
                if d.suggestion:
                    lines += ["", f"An older version passes the waiting period: npm install {d.suggestion}"]
                lines += ["", f"Nothing was installed. Install it anyway (only if you are sure): add {ALLOW_FLAG}"]
                console.print(Panel("\n".join(lines), title=f"HELD by Gatekeeper: {d.name}@{d.version} is too new", border_style="yellow"), markup=False)
                typer.echo("Gatekeeper held this install because the version was published very recently. "
                           + (f"You may install the older version {d.suggestion} instead, " if d.suggestion else "")
                           + "or ask the user.", err=True)
                raise typer.Exit(1)
            lines += ["", f"Nothing was installed. Override (only if you are sure): add {ALLOW_FLAG}"]
            console.print(Panel("\n".join(lines), title=f"BLOCKED by Gatekeeper: {d.name}@{d.version}", border_style="red"), markup=False)
            # message for AI coding agents reading stderr
            typer.echo("Gatekeeper blocked this install because the package looks malicious. Do not retry with other flags or names; ask the user.", err=True)
            raise typer.Exit(1)
    result = subprocess.run(real + [a for a in args if a != ALLOW_FLAG])
    raise typer.Exit(result.returncode)


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
        console.print(Panel(it.get("bundle") or f"(archived after 48 h: {it.get('bundle_archived', 'see the event logs')})",
                            title="evidence bundle", expand=False), markup=False, highlight=False)
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
            files = write_drafts({"name": it["name"], "version": it["version"], "excerpts": it.get("excerpts")}, full, reports_dir, note)
            console.print(f"[red]recorded as malicious[/]; report drafts: {files[0].rsplit(os.sep, 1)[0]}")
            console.print("Submit: npm 'Report malware' button on the package page (npm_report.txt), and a PR to ossf/malicious-packages (osv.json at the path in osv_path.txt).")
        else:
            console.print(f"recorded as {decision}")


@app.command()
def packet(
    key: str = typer.Argument(..., help="name@version of a queued flag"),
    reports_dir: str = typer.Option("data/reports", help="Where the packet and report drafts are written."),
) -> None:
    """Write a review packet (timeline, model verdicts, cited lines, hashes, install code, checklist)
    plus OSV and npm report drafts for one flagged version."""
    import os
    from pathlib import Path

    import modal

    from gatekeeper.report.drafts import write_drafts
    from gatekeeper.report.packet import RANK, build_packet
    from gatekeeper.worker.laptop import MonitorApi, load_env

    load_env()
    api = MonitorApi(os.environ["GK_API_URL"], os.environ["GK_WORKER_TOKEN"])
    it = api.item(key)
    inspection = modal.Function.from_name("gatekeeper", "inspect_package").remote(it["name"], it["version"])
    folder = Path(reports_dir) / f"{it['name'].replace('/', '__')}@{it['version']}"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "PACKET.md").write_text(build_packet(it, inspection), encoding="utf-8")
    judged = sorted((v for v in (it.get("verdicts") or {}).values() if v.get("full")),
                    key=lambda v: (-RANK.get(v.get("verdict"), -1), -(v.get("confidence") or 0)))
    if judged and not (folder / "osv.json").exists():  # never overwrite drafts a reviewer may have edited
        write_drafts({"name": it["name"], "version": it["version"], "excerpts": it.get("excerpts")}, judged[0]["full"], reports_dir)
    console.print(f"review packet: {folder / 'PACKET.md'}", markup=False)


@app.command("verify-flag")
def verify_flag(
    salt: str = typer.Argument(..., help="hex salt from revealed/<month>.jsonl"),
    line: str = typer.Argument(..., help="the canonical JSON line from revealed/<month>.jsonl"),
) -> None:
    """Check a revealed detection against the public ledger: hash it and find the batch that holds it."""
    import json

    from gatekeeper.ledger import LEDGER_REPO, commitment, find_batch, first_commit_with

    digest = commitment(salt, line)
    day = json.loads(line)["flagged_at"][:10]
    console.print(f"digest {digest}", markup=False)
    batch = find_batch(digest, day)
    if batch:
        console.print(f"found in {LEDGER_REPO}/{batch}", markup=False)
        console.print("Independent time proof (OpenTimestamps, Bitcoin-anchored): download the batch and its .ots, then run", markup=False)
        console.print(f"  ots verify {batch.rsplit('/', 1)[-1]}.ots", markup=False)
        return
    committed = first_commit_with(digest, day)  # early ledger format: one file per day, no .ots yet
    if committed:
        console.print(f"found in commitments/{day}.txt, first commit {committed}", markup=False)
        console.print("Note: this git date is self-asserted (unsigned commit); only later batches carry an OpenTimestamps proof.", markup=False)
    else:
        console.print("NOT FOUND in the ledger", markup=False)


if __name__ == "__main__":
    app()
