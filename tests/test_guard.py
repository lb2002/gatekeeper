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
