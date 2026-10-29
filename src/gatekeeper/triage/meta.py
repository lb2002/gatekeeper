"""T0: score a new package version from registry metadata alone (no archive download)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from gatekeeper.confirm.malindex import bad_dependencies
from gatekeeper.npm.packument import VersionInfo
from gatekeeper.triage.typosquat import typosquat_target

SYSTEM_COMMANDS = {"npm", "npx", "node", "git", "sh", "bash", "cmd", "powershell", "pwsh", "curl", "wget", "python", "pip", "sudo", "ls", "cd", "yarn", "pnpm"}


@dataclass
class MetaScore:
    score: int = 0
    reasons: list[str] = field(default_factory=list)

    def add(self, points: int, reason: str) -> None:
        self.score += points
        self.reasons.append(f"+{points} {reason}")


def score_metadata(
    info: VersionInfo,
    popular: set[str],
    now: datetime | None = None,
    mal_index: dict[str, dict] | None = None,
) -> MetaScore:
    now = now or datetime.now(timezone.utc)
    s = MetaScore()
    is_popular = info.name in popular

    if info.install_scripts:
        s.add(3, "install hook: " + ",".join(sorted(info.install_scripts)))
    if info.gypfile:
        s.add(2, "gypfile (build hook)")
    if is_popular and info.install_hook_added:
        s.add(6, "install hook newly added to a popular package")
    if is_popular and info.previous_version:
        if info.publisher and info.previous_publisher and info.publisher != info.previous_publisher:
            s.add(3, f"publisher changed {info.previous_publisher} -> {info.publisher}")
        if info.previous_maintainers and set(info.maintainers) - set(info.previous_maintainers):
            s.add(3, "new maintainer on a popular package")
    if info.package_created_at and now - info.package_created_at <= timedelta(hours=72):
        s.add(1, "package created in the last 72h")
    target = typosquat_target(info.name, popular)
    if target:
        s.add(3, f"name resembles popular package '{target}'")
    shadowed = sorted(set(info.bin) & SYSTEM_COMMANDS)
    if shadowed:
        s.add(3, "bin shadows system command: " + ",".join(shadowed))
    if not info.has_repository:
        s.add(1, "no repository field")
    # a clean-looking wrapper that installs known malware: enough to flag on its own (FLAG_TOTAL_THRESHOLD)
    for reason in bad_dependencies(info.dependencies, mal_index or {}, popular=popular)[:3]:
        s.add(2 if "from a URL" in reason else 9, reason)  # URL deps are sometimes legitimate: scan, do not flag
    return s
