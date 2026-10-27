"""npm/npx shims: a directory placed first on PATH whose `npm`/`npx` call `gk guard run`, which
checks the packages and then hands over to the real npm."""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

HOME = Path(os.environ.get("USERPROFILE") or Path.home()) / ".gatekeeper"
BIN = HOME / "bin"
CONFIG = HOME / "config.json"


def _real(tool: str) -> str | None:
    """Find the real npm/npx, skipping our own shim directory."""
    paths = [p for p in os.environ.get("PATH", "").split(os.pathsep) if p and Path(p).resolve() != BIN.resolve()]
    for ext in ([".cmd", ".exe", ""] if os.name == "nt" else [""]):
        found = shutil.which(tool + ext, path=os.pathsep.join(paths))
        if found:
            return found
    return None


def enable(gk_exe: str) -> dict:
    BIN.mkdir(parents=True, exist_ok=True)
    cfg = {"npm": _real("npm"), "npx": _real("npx"), "gk": gk_exe}
    if not cfg["npm"]:
        raise RuntimeError("real npm not found on PATH")
    CONFIG.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    for tool in ("npm", "npx"):
        (BIN / f"{tool}.cmd").write_text(f'@echo off\r\n"{gk_exe}" guard run {tool} -- %*\r\n', encoding="ascii")
        (BIN / f"{tool}.ps1").write_text(f'& "{gk_exe}" guard run {tool} -- @args\r\nexit $LASTEXITCODE\r\n', encoding="utf-8")
        sh = BIN / tool
        sh.write_text(f'#!/bin/sh\nexec "{Path(gk_exe).as_posix()}" guard run {tool} -- "$@"\n', encoding="ascii", newline="\n")
    return cfg


def config() -> dict:
    return json.loads(CONFIG.read_text(encoding="utf-8"))


def npm_command(cfg: dict, tool: str) -> list[str]:
    exe = cfg[tool]
    return [exe]
