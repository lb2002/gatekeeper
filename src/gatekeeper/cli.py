"""`gk` command line interface."""

from __future__ import annotations

import unicodedata
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import typer
from rich.console import Console
from rich.markup import escape
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
        table.add_row(str(s.score), escape(f"{info.name}@{info.version}"), escape("; ".join(s.reasons)))
    console.print(table)
    flagged = sum(1 for _, s in scored if s.score >= 3)
    console.print(f"score >= 3 (would go to archive scan): {flagged} of {len(scored)}")


@app.command("watch")
def watch(
    interval: float = typer.Option(5.0, help="Seconds between feed reads."),
    show_names: bool = typer.Option(False, "--show-names", help="Also print names of versions with notable signals "
                                    "(by default they are masked: a metadata signal is not an accusation)."),
    workers: int = typer.Option(8, help="Parallel packument fetches."),
) -> None:
    """Live view of new npm releases with their metadata signals, as the monitor sees them (nothing is downloaded)."""
    import hashlib
    import time

    popular = load_popular()
    seen: set[str] = set()
    total = notable = 0
    with feed.make_client() as client, ThreadPoolExecutor(max_workers=workers) as pool:
        since = feed.current_seq(client)
        console.print(f"[cyan]watching the npm registry feed from seq {since:,}[/] (Ctrl+C to stop)", highlight=False)

        def versions(name: str):
            try:
                doc = packument.fetch_packument(client, name)
            except Exception:
                return []
            if not doc:
                return []
            return [(i, score_metadata(i, popular)) for i in packument.recent_versions(doc, timedelta(minutes=10))
                    if not i.is_npm_placeholder]

        try:
            while True:
                batch, nxt = feed.fetch_changes(client, since, limit=200)
                names = list(dict.fromkeys(ch.name for ch in batch if not ch.deleted))
                since = max(since, nxt)
                for rows in pool.map(versions, names):
                    for info, s in rows:
                        key = f"{info.name}@{info.version}"
                        if key in seen:
                            continue
                        seen.add(key)
                        total += 1
                        when = info.published_at.strftime("%H:%M:%S") if info.published_at else "--:--:--"
                        # names and reasons are the publisher's text: escaped, never parsed as markup
                        reasons = escape("; ".join(s.reasons)[:70])
                        if s.score >= 5:
                            notable += 1
                            shown = escape(key if show_names else "pkg-" + hashlib.sha256(key.encode()).hexdigest()[:8])
                            console.print(f"{when}  [bold red]{s.score:>2}[/]  {shown:<48} [red]{reasons}[/]", highlight=False)
                        elif s.score >= 2:
                            console.print(f"{when}  [yellow]{s.score:>2}[/]  {escape(key[:48]):<48} [dim]{reasons}[/]",
                                          highlight=False)
                        else:
                            console.print(f"[dim]{when}  {s.score:>2}  {escape(key[:48])}[/]", highlight=False)
                time.sleep(interval)
        except KeyboardInterrupt:
            console.print(f"\n{total:,} new versions, {notable:,} with notable metadata signals (score >= 5)", highlight=False)


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
    console.print(f"[bold]{escape(name)}@{escape(version)}[/]  rules score {content.score}  ({', '.join(sorted(content.rules)) or 'no rule hits'})")
    if show_bundle:
        console.print(bundle.render(), markup=False, highlight=False)
    classify = {"spark": classify_spark, "fireworks": classify_spark_open_fireworks,
                "baseten": classify_spark_open_baseten}.get(backend, classify_local)
    result = classify(bundle)
    v = result.verdict
    if v is None:
        console.print(f"[red]model output unusable[/]: {escape(str(result.errors))}")
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
        console.print(f"[yellow]validation issues:[/] {escape(str(result.errors))}")


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
    """Download the local first-stage classifier (plain JSON, about 6 MB, no account needed)."""
    import httpx

    from gatekeeper.guard.core import FAST_MODEL_FILE, FAST_MODEL_URL, load_fast_model

    resp = httpx.get(FAST_MODEL_URL, timeout=120, follow_redirects=True)
    resp.raise_for_status()
    resp.json()  # parse before replacing the old model
    FAST_MODEL_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = FAST_MODEL_FILE.with_suffix(".tmp")
    tmp.write_bytes(resp.content)
    tmp.replace(FAST_MODEL_FILE)
    model = load_fast_model()
    console.print(f"local classifier: {len(model.index):,} terms, threshold {model.threshold:.3f}", markup=False)


@guard_app.command("setup")
def guard_setup() -> None:
    """Everything the guard needs in one step: the npm/npx shims, the list of known malware, the local classifier."""
    import os

    import httpx

    from gatekeeper.guard import shim
    from gatekeeper.models.backends import LOCAL_URL

    guard_enable()
    guard_update_osv(from_osv=False)
    guard_update_model()
    try:
        httpx.get(f"{LOCAL_URL}/models", timeout=2).raise_for_status()
        console.print(f"Muse Glimmer: running at {LOCAL_URL}", markup=False)
    except httpx.HTTPError:
        console.print("Muse Glimmer: not running. Known malware, private dependencies and brand-new versions are still "
                      "stopped; a package the rules flag is blocked until the model can judge it (see the README).", markup=False)
    if os.name == "nt":
        console.print("Ready. Start a guarded shell with: gk guard shell", markup=False)
    else:
        console.print(f'Ready. Add this to your shell profile: export PATH="{shim.BIN}:$PATH"', markup=False)


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
    from gatekeeper.guard.core import ALLOW_FLAG, check_spec, index_age_days, load_fast_model, npm_native_parse, with_before

    # the shims call `gk guard run npm -- <args>`: drop that one separator, keep the user's own `--`
    args = list(ctx.args[1:] if ctx.args[:1] == ["--"] else ctx.args)
    cfg = shim.config()
    real = shim.npm_command(cfg, tool)
    allow = ALLOW_FLAG in args
    plain = [a for a in args if a != ALLOW_FLAG]
    # the waiting period the real install will run with: resolve with the same cutoff, check what gets installed
    final = plain if allow else with_before(tool, plain)
    before = [a for a in final if a not in plain]
    native = None if allow else npm_native_parse(shim.npm_command(cfg, tool)[0], tool, final)
    if native is not None and native.get("command") in ("view", "outdated", "search"):
        final, before = plain, []  # read-only: --before would only change what the user sees
    if native is not None:
        remote = [x["spec"] for x in native["specs"] if x["type"] in ("remote", "invalid")]
        resolved = {x["spec"]: x for x in native["specs"] if x["type"] == "registry"}
    elif not allow:
        # Never fall back to guessing: a broken .npmrc or a slow registry must not reopen what npm's own parse closed.
        console.print(Panel("Gatekeeper could not ask npm which packages this command would install or run (npm's "
                            "own argument parsing failed or timed out), so nothing was run.\n\n"
                            f"Check your .npmrc / npm_config_* settings, or add {ALLOW_FLAG} if you are sure.",
                            title="BLOCKED by Gatekeeper: could not check", border_style="red"), markup=False)
        typer.echo("Gatekeeper could not check this npm command. Do not retry with other flags; ask the user.", err=True)
        raise typer.Exit(1)
    else:
        remote, resolved = [], {}
    if remote and not allow:
        console.print(Panel("\n".join(["npm would use sources Gatekeeper cannot check:", *[f"  - {r}" for r in remote], "",
                                        "Code from git or a URL, a package-lock.json entry outside the registry, or a registry, proxy",
                                        "or TLS setting in the project's own .npmrc (a cloned repository controls these files).",
                                        "", f"Nothing was run. If you trust the source: add {ALLOW_FLAG}, or GK_TRUST_PROJECT_REGISTRY=1 "
                                        "for the project's .npmrc"]),
                            title="BLOCKED by Gatekeeper: unchecked source", border_style="red"), markup=False)
        typer.echo("Gatekeeper blocked npm because it would use a source Gatekeeper cannot check. Do not retry with other "
                   "flags; ask the user.", err=True)
        raise typer.Exit(1)
    specs = list(resolved)
    if specs and not allow:
        fast_model = load_fast_model()
        stale = index_age_days()
        if stale is None or stale > 3:
            console.print("[yellow]gatekeeper[/] the offline OSV malware list is "
                          + ("missing" if stale is None else f"{stale:.0f} days old") + "; run `gk guard update-osv`", highlight=False)
        for spec in specs:
            console.print(f"[cyan]gatekeeper[/] checking {escape(spec)} ...", highlight=False)
            try:
                r = resolved.get(spec)
                if r is not None and r.get("error"):
                    raise RuntimeError(f"npm could not resolve it ({r['error'].strip()[:200]})")
                meta = None if r is None else {k: r[k] for k in ("name", "version", "tarball", "integrity", "time", "dependencies")}
                if r is not None and r.get("requested_version"):
                    console.print(f"[dim]gatekeeper: npm will install {escape(r['name'])}@{escape(r['version'])}, the newest match "
                                  f"older than the waiting period ({escape(r['requested_version'])} is newer)[/]", highlight=False)
                d = check_spec(shim.npm_command(cfg, "npm"), spec, fast_model=fast_model, meta=meta)
            except Exception as exc:
                # Fail closed: a package must not get through just because checking it failed
                # (an attacker could craft an archive that makes the check error out).
                console.print(f"[red]gatekeeper could not check {escape(spec)}: {escape(str(exc))}; blocked[/]", highlight=False)
                console.print(f"If you are sure the package is safe, re-run with {ALLOW_FLAG}.", markup=False)
                typer.echo("Gatekeeper could not verify this package, so nothing was installed. Do not retry with other flags; ask the user.", err=True)
                raise typer.Exit(1)
            if d.allowed:
                console.print(f"[green]allowed[/] {escape(d.name)}@{escape(d.version)}: {escape(d.reason)} ({d.seconds:.1f}s)", highlight=False)
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
    resolving = native is not None and native.get("command") in ("install", "install-test", "update", "dedupe", "link",
                                                                 "exec", "init", "audit", "ci", "install-ci-test")
    if before and resolving:
        console.print(f"[dim]gatekeeper: dependencies limited to versions published {before[0][9:]} or earlier "
                      f"(waiting period; GK_MIN_AGE_HOURS=0 turns it off)[/]", highlight=False)
    result = subprocess.run(real + final)
    if result.returncode and before:
        console.print("[yellow]gatekeeper[/] if npm could not find a version (ETARGET), a dependency may require a release "
                      f"younger than the waiting period. If you trust it, re-run with {ALLOW_FLAG}.", highlight=False)
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


def plain(text: object) -> str:
    """Text a package author can influence (paths, model summaries) as one safe terminal line: no escape sequences,
    no line breaks that could fake a verdict line, no invisible or bidirectional characters."""
    return "".join("?" if unicodedata.category(c)[0] == "C" or unicodedata.category(c) in ("Zl", "Zp") else c
                   for c in " ".join(str(text).split()))


@app.command()
def investigate(
    key: str = typer.Argument(..., help="name@version of a package on npm"),
    backend: str = typer.Option("spark-open-baseten", help="spark-open-baseten, spark-open-fireworks or spark"),
) -> None:
    """Let a Muse model investigate one package and print what it looked at. Runs in the Modal container: the
    archive stays in memory there, nothing is executed and nothing reaches this machine but text."""
    import modal
    from rich.markup import escape

    name, _, version = key.rpartition("@")
    res = modal.Function.from_name("gatekeeper", "investigate_package").remote(name, version, True, backend)
    if res.get("error"):
        console.print(res["error"], markup=False)
        raise typer.Exit(1)
    for i, step in enumerate(res["steps"], start=1):
        target = ", ".join(step["terms"]) if step["action"] == "search" else step["path"]
        console.print(f"[bold]{i}. {escape(plain(step['action']))}[/bold] {escape(plain(target))}  [dim]{escape(plain(step['reason']))}[/dim]")
    v = res.get("verdict")
    if not v:
        console.print(plain(f"no verdict: {res['errors']}"), markup=False)
        raise typer.Exit(1)
    color = {"malicious": "red", "suspicious": "yellow"}.get(v["verdict"], "green")
    console.print(f"[bold {color}]{v['verdict'].upper()}[/bold {color}] {v['confidence']:.2f}  {escape(plain(v['category']))}")
    console.print(plain(v["summary"]), markup=False)
    for ev in v["evidence"]:
        console.print(plain(f"  {ev['excerpt_id']} lines {ev['line_start']}-{ev['line_end']}: {ev['why']}"), markup=False)
    for err in res["errors"]:
        console.print(f"[yellow]not verified:[/yellow] {escape(plain(err))}")
    console.print(f"[dim]{len(res['steps'])} steps, ${res['cost_usd']:.4f}[/dim]")


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
