import io
import tarfile

import pytest

from gatekeeper.npm import tarball
from gatekeeper.npm.tarball import ArchiveTooLarge, normalize_member_path, read_tarball


def make_tgz(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def test_reads_files_and_strips_package_prefix():
    data = make_tgz({"package/package.json": b'{"name":"x"}', "package/lib/index.js": b"module.exports=1"})
    pkg = read_tarball(data)
    assert pkg.text("package.json") == '{"name":"x"}'
    assert "lib/index.js" in pkg.files


@pytest.mark.parametrize("bad", ["/etc/passwd", "../../evil.js", "package/../../x"])
def test_rejects_escaping_paths(bad):
    assert normalize_member_path(bad) is None


def test_truncates_large_files(monkeypatch):
    monkeypatch.setattr(tarball, "MAX_FILE_BYTES", 10)
    pkg = read_tarball(make_tgz({"package/big.js": b"a" * 100}))
    assert len(pkg.files["big.js"]) == 10
    assert pkg.sizes["big.js"] == 100
    assert "big.js" in pkg.truncated


def test_stops_at_member_cap(monkeypatch):
    monkeypatch.setattr(tarball, "MAX_MEMBERS", 3)
    pkg = read_tarball(make_tgz({f"package/f{i}.js": b"x" for i in range(10)}))
    assert len(pkg.files) == 3
    assert pkg.skipped_members == 1


def test_rejects_oversized_archive(monkeypatch):
    monkeypatch.setattr(tarball, "MAX_COMPRESSED_BYTES", 10)
    with pytest.raises(ArchiveTooLarge):
        read_tarball(make_tgz({"package/a.js": b"x" * 1000}))
