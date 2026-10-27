"""Read npm package archives entirely in memory.

Nothing is ever extracted to disk and nothing is ever executed. Hard caps protect against
decompression bombs and archives with huge numbers of files.
"""

from __future__ import annotations

import io
import posixpath
import tarfile
from dataclasses import dataclass, field

MAX_COMPRESSED_BYTES = 5 * 1024 * 1024
MAX_MEMBERS = 300
MAX_FILE_BYTES = 1024 * 1024
MAX_TOTAL_BYTES = 20 * 1024 * 1024
MAX_DECLARED_BYTES = 200 * 1024 * 1024  # stop before decompressing more than this


class ArchiveTooLarge(Exception):
    pass


@dataclass
class PackageFiles:
    files: dict[str, bytes] = field(default_factory=dict)  # normalized path -> content (possibly truncated)
    sizes: dict[str, int] = field(default_factory=dict)  # normalized path -> real size
    truncated: list[str] = field(default_factory=list)
    skipped_members: int = 0

    def text(self, path: str) -> str | None:
        data = self.files.get(path)
        if data is None:
            return None
        return data.decode("utf-8", errors="replace")


def normalize_member_path(name: str) -> str | None:
    """Strip the leading package/ directory and reject absolute or escaping paths."""
    name = name.replace("\\", "/")
    if name.startswith("/"):
        return None
    norm = posixpath.normpath(name)
    if norm.startswith("..") or norm == ".":
        return None
    parts = norm.split("/", 1)
    return parts[1] if len(parts) == 2 else parts[0]


def read_tarball(data: bytes) -> PackageFiles:
    if len(data) > MAX_COMPRESSED_BYTES:
        raise ArchiveTooLarge(f"compressed archive is {len(data)} bytes")
    out = PackageFiles()
    total = 0
    declared = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tar:
        for count, member in enumerate(tar):
            if count >= MAX_MEMBERS:
                out.skipped_members += 1
                break
            declared += max(member.size, 0)
            if declared > MAX_DECLARED_BYTES:
                out.skipped_members += 1
                break
            if not member.isfile():
                continue
            path = normalize_member_path(member.name)
            if path is None:
                out.skipped_members += 1
                continue
            out.sizes[path] = member.size
            budget = min(MAX_FILE_BYTES, MAX_TOTAL_BYTES - total)
            if budget <= 0:
                out.truncated.append(path)
                continue
            handle = tar.extractfile(member)
            if handle is None:
                continue
            content = handle.read(budget)
            if member.size > len(content):
                out.truncated.append(path)
            out.files[path] = content
            total += len(content)
    return out
