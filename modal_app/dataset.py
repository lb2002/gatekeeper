"""Build the training/evaluation datasets on Modal.

Malware samples (DataDog malicious-software-packages-dataset, zip password per their README) are
only ever decrypted in memory inside these containers. The output contains text bundles only.

Run:  uv run modal run modal_app/dataset.py::inspect
"""

import json
import subprocess
from pathlib import Path

import modal

app = modal.App("gatekeeper-dataset")
image = (
    modal.Image.debian_slim(python_version="3.12")
    .apt_install("git")
    .pip_install("httpx>=0.27", "pydantic>=2.7", "typer>=0.12", "rich>=13.7", "pyzipper>=0.3.6")
    .add_local_python_source("gatekeeper")
)
volume = modal.Volume.from_name("gatekeeper-data", create_if_missing=True)
DATA = Path("/data")
REPO = "https://github.com/DataDog/malicious-software-packages-dataset.git"
CLONE = Path("/tmp/ddset")


def _clone() -> Path:
    if not CLONE.exists():
        subprocess.run(["git", "clone", "--depth", "1", "--filter=blob:none", "--sparse", REPO, str(CLONE)], check=True)
        subprocess.run(["git", "-C", str(CLONE), "sparse-checkout", "set", "samples/npm"], check=True)
    return CLONE / "samples" / "npm"


@app.function(image=image, timeout=1800, cpu=1.0, memory=2048)
def inspect() -> dict:
    """Describe the npm part of the dataset: counts, manifest shape, and member names of one sample."""
    import pyzipper

    root = _clone()
    zips = sorted(root.rglob("*.zip"))
    by_kind: dict[str, int] = {}
    for z in zips:
        kind = z.relative_to(root).parts[0]
        by_kind[kind] = by_kind.get(kind, 0) + 1
    manifest_path = root / "manifest.json"
    manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else {}
    sample_members: list[str] = []
    if zips:
        with pyzipper.AESZipFile(zips[-1]) as zf:
            sample_members = [i.filename for i in zf.infolist()][:20]
    dates = sorted(z.name[:10] for z in zips)
    out = {
        "zips": len(zips),
        "by_kind": by_kind,
        "first_date": dates[0] if dates else None,
        "last_date": dates[-1] if dates else None,
        "per_month": {},
        "manifest_entries": len(manifest),
        "manifest_example": list(manifest.items())[:3],
        "sample_path": str(zips[-1].relative_to(root)) if zips else None,
        "sample_members": sample_members,
        "total_mb": round(sum(z.stat().st_size for z in zips) / 1e6, 1),
    }
    for d in dates:
        out["per_month"][d[:7]] = out["per_month"].get(d[:7], 0) + 1
    print(json.dumps(out, indent=1)[:6000])
    return out


TRAIN_END = "2026-05-31"  # train on discovery dates up to here
TEST_START = "2026-07-01"  # June is a gap; July has no samples in the dataset
TRAIN_CANDIDATES = 4500
MAX_PER_CLUSTER = 3
SEED = 20261027


def _list_paths() -> list[str]:
    """List sample paths without downloading blobs (blobless clone)."""
    if not CLONE.exists():
        subprocess.run(["git", "clone", "--depth", "1", "--filter=blob:none", "--no-checkout", REPO, str(CLONE)], check=True)
    out = subprocess.run(
        ["git", "-C", str(CLONE), "ls-tree", "-r", "--name-only", "HEAD", "samples/npm"],
        check=True, capture_output=True, text=True,
    ).stdout
    return [p for p in out.splitlines() if p.endswith(".zip")]


def _parse(path: str) -> dict:
    # samples/npm/<kind>/<pkg...>/<version>/<YYYY-MM-DD>-<pkg>-v<version>.zip ; scoped pkgs have two segments
    parts = path.split("/")
    kind, version, fname = parts[2], parts[-2], parts[-1]
    name = "/".join(parts[3:-2])
    return {"path": path, "kind": kind, "name": name, "version": version, "date": fname[:10]}


def _blob(path: str) -> bytes:
    return subprocess.run(["git", "-C", str(CLONE), "cat-file", "blob", f"HEAD:{path}"], check=True, capture_output=True).stdout


def _package_from_zip(data: bytes):
    """Decrypt in memory and rebuild PackageFiles from the extracted package folder inside the zip."""
    import io

    import pyzipper

    from gatekeeper.npm import tarball as tb

    pkg = tb.PackageFiles()
    info: dict = {}
    total = 0
    with pyzipper.AESZipFile(io.BytesIO(data)) as zf:
        zf.setpassword(b"infected")
        for zi in zf.infolist()[: tb.MAX_MEMBERS * 2]:
            if zi.is_dir():
                continue
            name = zi.filename.replace("\\", "/")
            if "/package_info-" in name and name.endswith(".json"):
                try:
                    info = json.loads(zf.read(zi).decode("utf-8", "replace"))
                except ValueError:
                    info = {}
                continue
            if "/package/" not in name:
                continue
            rel = name.split("/package/", 1)[1]
            if not rel or rel.startswith("/") or ".." in rel.split("/"):
                continue
            pkg.sizes[rel] = zi.file_size
            if len(pkg.files) >= tb.MAX_MEMBERS or total >= tb.MAX_TOTAL_BYTES:
                pkg.truncated.append(rel)
                continue
            with zf.open(zi) as fh:
                content = fh.read(tb.MAX_FILE_BYTES)
            pkg.files[rel] = content
            total += len(content)
    return pkg, info


def _cluster_key(pkg) -> str:
    """Hash of the code that matters (install-time + focus files), whitespace-normalized."""
    import hashlib
    import re

    from gatekeeper.triage.content import focus_files, install_time_files

    h = hashlib.sha256()
    for path in sorted(set(focus_files(pkg)) | set(install_time_files(pkg)) - {"package.json"}):
        h.update(re.sub(rb"\s+", b"", pkg.files.get(path, b""))[:20000])
    raw = pkg.text("package.json") or ""
    try:
        scripts = json.loads(raw).get("scripts") or {}
    except (ValueError, AttributeError):
        scripts = {}
    h.update(json.dumps(scripts, sort_keys=True).encode())
    return h.hexdigest()[:16]


def _record(meta: dict, pkg, label: str, split: str, extra: dict | None = None) -> dict:
    from gatekeeper.evidence.bundle import build_bundle
    from gatekeeper.triage.content import score_content

    content = score_content(pkg)
    bundle = build_bundle(meta["name"], meta["version"], pkg, content)
    return {
        "split": split,
        "label": label,
        "kind": meta.get("kind", "benign"),
        "name": meta["name"],
        "version": meta["version"],
        "date": meta.get("date"),
        "content_score": content.score,
        "rules": sorted(content.rules),
        "cluster": _cluster_key(pkg),
        "bundle": bundle.render(),
        "excerpts": [e.ref() for e in bundle.excerpts],
        **(extra or {}),
    }


@app.function(image=image, volumes={str(DATA): volume}, timeout=3 * 3600, cpu=4.0, memory=8192)
def build_malicious() -> dict:
    """Malicious train/test bundles with a time split and campaign (cluster) dedup."""
    import random
    from concurrent.futures import ThreadPoolExecutor

    rows = [_parse(p) for p in _list_paths()]
    latest: dict[tuple[str, str], dict] = {}
    for r in rows:  # one version per package, latest discovery date, per kind
        k = (r["kind"], r["name"])
        if k not in latest or r["date"] > latest[k]["date"]:
            latest[k] = r
    pool = list(latest.values())
    train_pool = [r for r in pool if r["date"] <= TRAIN_END]
    test_pool = [r for r in pool if r["date"] >= TEST_START]
    rng = random.Random(SEED)
    rng.shuffle(train_pool)
    # keep every compromised_lib sample (rare, important) and sample the rest
    train_sel = [r for r in train_pool if r["kind"] == "compromised_lib"]
    train_sel += [r for r in train_pool if r["kind"] != "compromised_lib"][: max(0, TRAIN_CANDIDATES - len(train_sel))]
    selected = [(r, "train") for r in train_sel] + [(r, "test") for r in test_pool]

    def work(item):
        r, split = item
        try:
            pkg, info = _package_from_zip(_blob(r["path"]))
            if not pkg.files:
                return None
            return _record(r, pkg, "malicious", split, {"info_keys": sorted(info)[:20]})
        except Exception as exc:
            return {"error": f"{type(exc).__name__}: {exc}"[:200], "path": r["path"]}

    with ThreadPoolExecutor(max_workers=16) as ex:
        results = [x for x in ex.map(work, selected) if x is not None]
    errors = [x for x in results if "error" in x]
    good = [x for x in results if "error" not in x]
    per_cluster: dict[tuple[str, str], int] = {}
    kept = []
    for x in good:
        ck = (x["split"], x["cluster"])
        if per_cluster.get(ck, 0) < MAX_PER_CLUSTER:
            per_cluster[ck] = per_cluster.get(ck, 0) + 1
            kept.append(x)
    # a cluster seen in training must not leak into the test set
    train_clusters = {x["cluster"] for x in kept if x["split"] == "train"}
    leaked = [x for x in kept if x["split"] == "test" and x["cluster"] in train_clusters]
    kept = [x for x in kept if not (x["split"] == "test" and x["cluster"] in train_clusters)]
    out = DATA / "datasets" / "malicious.jsonl"
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as fh:
        for x in kept:
            fh.write(json.dumps(x, ensure_ascii=False) + "\n")
    volume.commit()
    stats = {
        "candidates": len(selected), "errors": len(errors), "processed": len(good),
        "kept_train": sum(x["split"] == "train" for x in kept), "kept_test": sum(x["split"] == "test" for x in kept),
        "dropped_test_leaks": len(leaked), "clusters": len(per_cluster), "error_examples": errors[:3],
    }
    print(json.dumps(stats))
    return stats


BUN_TRUSTED_URL = "https://raw.githubusercontent.com/oven-sh/bun/main/src/install/default-trusted-dependencies.txt"
BENIGN_TOP = 2500


@app.function(image=image, volumes={str(DATA): volume}, timeout=2 * 3600, cpu=2.0, memory=4096)
def build_benign() -> dict:
    """Benign bundles: top npm packages plus Bun's trusted packages with install scripts (hard negatives).
    Split 80/20 by package so train and test never share a package."""
    import random
    import zlib
    from concurrent.futures import ThreadPoolExecutor

    import httpx

    from gatekeeper.npm import feed, packument
    from gatekeeper.npm.tarball import read_tarball
    from gatekeeper.popular import load_popular, parse_top_js

    with httpx.Client(timeout=60, follow_redirects=True) as c:
        top_src = c.get("https://raw.githubusercontent.com/wooorm/npm-high-impact/main/lib/top-download.js").text
        bun = [l.strip() for l in c.get(BUN_TRUSTED_URL).text.splitlines() if l.strip() and not l.startswith("#")]
    top = parse_top_js(top_src)[:BENIGN_TOP]
    hard = set(bun)
    names = list(dict.fromkeys(bun + top))
    known_bad = set(_known_malicious_names())

    def work(name: str):
        if name in known_bad:
            return None
        try:
            with feed.make_client() as client:
                doc = packument.fetch_packument(client, name)
                if not doc:
                    return None
                ver = (doc.get("dist-tags") or {}).get("latest")
                info = packument.version_info(doc, ver)
                if not info.tarball_url:
                    return None
                data = client.get(info.tarball_url).content
            pkg = read_tarball(data)
            split = "test" if zlib.crc32(name.encode()) % 5 == 0 else "train"
            return _record({"name": name, "version": ver, "date": info.published_at.isoformat() if info.published_at else None},
                           pkg, "benign", split, {"hard_negative": name in hard})
        except Exception as exc:
            return {"error": f"{type(exc).__name__}: {exc}"[:200], "name": name}

    with ThreadPoolExecutor(max_workers=24) as ex:
        results = [x for x in ex.map(work, names) if x is not None]
    errors = [x for x in results if "error" in x]
    good = [x for x in results if "error" not in x]
    out = DATA / "datasets" / "benign.jsonl"
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as fh:
        for x in good:
            fh.write(json.dumps(x, ensure_ascii=False) + "\n")
    volume.commit()
    stats = {
        "names": len(names), "errors": len(errors), "kept": len(good),
        "train": sum(x["split"] == "train" for x in good), "test": sum(x["split"] == "test" for x in good),
        "hard_negatives": sum(x.get("hard_negative", False) for x in good),
    }
    print(json.dumps(stats))
    return stats


def _known_malicious_names() -> list[str]:
    """Package names in the DataDog manifest (any version malicious) are never used as benign."""
    try:
        _list_paths()
        raw = subprocess.run(["git", "-C", str(CLONE), "show", "HEAD:samples/npm/manifest.json"], check=True, capture_output=True).stdout
        return list(json.loads(raw))
    except Exception:
        return []


@app.function(image=image, volumes={str(DATA): volume}, timeout=2 * 3600, cpu=4.0, memory=8192)
def build_deep(split: str = "test", max_chars: int = 24000) -> dict:
    """The same packages as the `split` rows, with a larger evidence budget: the "closer look" a second
    stage gives only to what the cheap first stage flagged. Malware is decrypted in memory as before."""
    from concurrent.futures import ThreadPoolExecutor

    from gatekeeper.evidence.bundle import build_bundle
    from gatekeeper.npm import feed, packument
    from gatekeeper.npm.tarball import read_tarball
    from gatekeeper.triage.content import score_content

    rows = []
    for name in ("malicious.jsonl", "benign.jsonl"):
        rows += [json.loads(l) for l in (DATA / "datasets" / name).read_text(encoding="utf-8").splitlines() if l.strip()]
    rows = [r for r in rows if r["split"] == split]
    paths = {(m["name"], m["version"]): m["path"] for m in map(_parse, _list_paths())}

    def work(r: dict):
        try:
            if r["label"] == "malicious":
                pkg, _ = _package_from_zip(_blob(paths[(r["name"], r["version"])]))
            else:
                with feed.make_client() as client:
                    info = packument.version_info(packument.fetch_packument(client, r["name"]), r["version"])
                    pkg = read_tarball(client.get(info.tarball_url).content)
            content = score_content(pkg)
            b = build_bundle(r["name"], r["version"], pkg, content, max_chars=max_chars)
            return r | {"bundle": b.render(), "excerpts": [e.ref() for e in b.excerpts]}
        except Exception as exc:
            return {"error": f"{type(exc).__name__}: {exc}"[:200], "name": r["name"]}

    with ThreadPoolExecutor(max_workers=16) as ex:
        results = list(ex.map(work, rows))
    good = [x for x in results if "error" not in x]
    out = DATA / "datasets" / f"deep-{split}.jsonl"
    with out.open("w", encoding="utf-8") as fh:
        for x in good:
            fh.write(json.dumps(x, ensure_ascii=False) + "\n")
    volume.commit()
    stats = {"rows": len(rows), "built": len(good), "errors": [x for x in results if "error" in x][:5],
             "mean_chars": round(sum(len(x["bundle"]) for x in good) / max(len(good), 1))}
    print(json.dumps(stats))
    return stats
