import base64
import hashlib

from gatekeeper.guard.core import package_specs, verify_integrity


def test_install_specs_skip_flags_and_local_paths():
    args = ["install", "-D", "axios-retry@^4", "@types/node", "./local-dir", "file:../x", "--registry", "https://r.example", "lodash"]
    assert package_specs("npm", args) == ["axios-retry@^4", "@types/node", "lodash"]


def test_non_install_commands_are_not_checked():
    assert package_specs("npm", ["run", "build"]) == []
    assert package_specs("npm", ["install"]) == []  # lockfile install: out of scope for now
    assert package_specs("npm", ["test"]) == []


def test_exec_and_npx():
    assert package_specs("npx", ["-y", "create-vite@latest", "my-app"]) == ["create-vite@latest"]
    assert package_specs("npm", ["exec", "cowsay"]) == ["cowsay"]


def test_allow_flag_is_ignored_in_specs():
    assert package_specs("npm", ["i", "--gk-allow", "left-pad"]) == ["left-pad"]


def test_integrity_check():
    data = b"tarball bytes"
    good = "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode()
    assert verify_integrity(data, good)
    assert not verify_integrity(b"tampered", good)
    assert verify_integrity(data, "sha1-abc")  # only sha512 is checked here


def test_rules_clean_but_classifier_suspicious_goes_to_the_model(monkeypatch):
    import gatekeeper.guard.core as core

    class Model:
        threshold = 0.5

        def risk(self, *a):
            return 0.9

    monkeypatch.setattr(core, "resolve", lambda cmd, spec: {"name": "quiet", "version": "1.0.0", "tarball": "x", "integrity": None})
    monkeypatch.setattr(core.httpx, "get", lambda *a, **k: type("R", (), {"content": b""})())
    monkeypatch.setattr(core, "verify_integrity", lambda data, integrity: True)
    from gatekeeper.npm.tarball import PackageFiles

    pkg = PackageFiles()
    pkg.files["package.json"] = b'{"name":"quiet"}'
    pkg.sizes["package.json"] = 16
    monkeypatch.setattr(core, "read_tarball", lambda data: pkg)
    asked = []

    def classify(bundle):
        asked.append(bundle)
        raise RuntimeError("model called")

    try:
        core.check_spec(["npm"], "quiet", classify=classify, fast_model=Model())
    except RuntimeError:
        pass
    assert asked, "a package the classifier flags must not take the rules-only fast path"
