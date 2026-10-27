"""Minimal local npm registry for the demo on 127.0.0.1:4873 (stdlib only).

Serves the packages in DEMO_PACKAGES from their folders here, packed in memory, and passes every
other read through to registry.npmjs.org so normal packages still install. Nothing is published
anywhere; stop it with Ctrl+C.
"""

import base64
import gzip
import hashlib
import io
import json
import tarfile
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HOST, PORT = "127.0.0.1", 4873
BASE = f"http://{HOST}:{PORT}"
UPSTREAM = "https://registry.npmjs.org"
DEMO_PACKAGES = {"axois-retry": Path(__file__).parent / "villain-pkg"}


def pack(folder: Path) -> bytes:
    """npm-style tarball (files under package/), byte-for-byte reproducible."""
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tar:
        for f in sorted(p for p in folder.rglob("*") if p.is_file()):
            data = f.read_bytes()
            info = tarfile.TarInfo("package/" + f.relative_to(folder).as_posix())
            info.size, info.mode, info.mtime = len(data), 0o644, 499162500  # npm's fixed mtime
            tar.addfile(info, io.BytesIO(data))
    out = io.BytesIO()
    with gzip.GzipFile(fileobj=out, mode="wb", mtime=0) as gz:
        gz.write(raw.getvalue())
    return out.getvalue()


def packument(name: str, folder: Path) -> tuple[dict, bytes]:
    manifest = json.loads((folder / "package.json").read_text())
    version = manifest["version"]
    tgz = pack(folder)
    dist = {
        "tarball": f"{BASE}/{name}/-/{name}-{version}.tgz",
        "shasum": hashlib.sha1(tgz).hexdigest(),
        "integrity": "sha512-" + base64.b64encode(hashlib.sha512(tgz).digest()).decode(),
    }
    doc = {
        "name": name,
        "dist-tags": {"latest": version},
        "versions": {version: manifest | {"_id": f"{name}@{version}", "dist": dist}},
        "time": {"created": "2026-10-27T00:00:00.000Z", version: "2026-10-27T00:00:00.000Z"},
    }
    return doc, tgz


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = urllib.request.unquote(self.path.split("?", 1)[0]).lstrip("/")
        name = path.split("/-/", 1)[0]
        if name in DEMO_PACKAGES:
            doc, tgz = packument(name, DEMO_PACKAGES[name])
            if "/-/" in path:
                return self._send(200, tgz, "application/octet-stream")
            return self._send(200, json.dumps(doc).encode(), "application/json")
        try:
            req = urllib.request.Request(f"{UPSTREAM}{self.path}", headers={"Accept": self.headers.get("Accept", "*/*")})
            with urllib.request.urlopen(req, timeout=60) as r:
                self._send(r.status, r.read(), r.headers.get("Content-Type", "application/json"))
        except urllib.error.HTTPError as e:
            self._send(e.code, e.read(), "application/json")

    def do_PUT(self):
        self._send(405, b'{"error":"read-only demo registry"}', "application/json")

    def _send(self, code: int, body: bytes, ctype: str):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        print("registry:", fmt % args)


if __name__ == "__main__":
    print(f"demo registry on {BASE} (demo packages: {', '.join(DEMO_PACKAGES)}; everything else from npmjs)")
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
