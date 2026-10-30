"""Comparing a version with its predecessor or the package it was copied from."""

import json

import httpx

from gatekeeper.evidence.compare import Reference, added_runs, fork_candidates, references_for, shared_paths
from gatekeeper.investigate import diff_excerpts
from gatekeeper.npm.tarball import PackageFiles


def pkg_of(files: dict[str, str]) -> PackageFiles:
    data = {p: t.encode() for p, t in files.items()}
    return PackageFiles(files=data, sizes={p: len(b) for p, b in data.items()})


LIB = "\n".join(f"function f{i}() {{ return {i} }}" for i in range(400))


def test_an_injected_call_is_found_in_a_large_file():
    old = pkg_of({"lib/socket.js": LIB})
    new = pkg_of({"lib/socket.js": LIB.replace("function f200()", "setTimeout(() => follow('1203'), 9e4)\nfunction f200()")})
    runs = added_runs(new, old)
    assert len(runs) == 1 and runs[0].first_line == 201 and "follow('1203')" in runs[0].lines[0]


def test_reformatting_alone_adds_nothing():
    old = pkg_of({"a.js": "const a = 1\nconst b = 2\n"})
    new = pkg_of({"a.js": "const  a  =  1\n\n  const b = 2\n"})
    assert added_runs(new, old) == []


def test_new_files_are_listed_after_changes_in_existing_ones():
    old = pkg_of({"a.js": "x\n"})
    new = pkg_of({"a.js": "x\nfetch('https://a.example')\n", "b.js": "fetch('https://b.example')\n"})
    runs = added_runs(new, old)
    assert [r.path for r in runs] == ["a.js", "b.js"] and runs[1].new_file


def test_risky_additions_come_before_plain_ones():
    old = pkg_of({"a.js": "x\n"})
    new = pkg_of({"a.js": "x\nconst label = 'hello'\n\n\nrequire('child_process').exec(cmd)\n"})
    runs = added_runs(new, old)
    assert "child_process" in runs[0].lines[-1]


def test_typing_files_and_other_assets_are_ignored():
    assert added_runs(pkg_of({"a.d.ts": "x", "logo.svg": "x", "readme.md": "x"}), pkg_of({})) == []


def test_shared_paths_tells_a_copy_from_a_stranger():
    new = pkg_of({"a.js": "1", "b.js": "2", "c.js": "3"})
    assert shared_paths(new, pkg_of({"a.js": "x", "b.js": "y"})) == 2 / 3
    assert shared_paths(pkg_of({"readme.md": "x"}), pkg_of({})) == 0.0


POPULAR = {"@whiskeysockets/baileys", "express", "lodash", "react"}


def test_fork_found_by_its_kept_repository_link():
    manifest = {"repository": {"url": "git+https://github.com/WhiskeySockets/Baileys.git"}}
    assert fork_candidates("saturn-bail", manifest, POPULAR) == ["@whiskeysockets/baileys"]


def test_fork_found_by_the_original_name_inside_its_own():
    assert fork_candidates("kiki-baileys", {}, POPULAR) == ["@whiskeysockets/baileys"]
    assert fork_candidates("@someone/baileys2", {}, POPULAR) == ["@whiskeysockets/baileys"]


def test_a_package_is_not_its_own_fork():
    assert fork_candidates("@whiskeysockets/baileys", {"homepage": "https://github.com/WhiskeySockets/Baileys"}, POPULAR) == []


def test_generic_words_do_not_make_a_fork():
    assert fork_candidates("my-tool", {"homepage": "https://github.com/me/my-tool"}, {"github", "tool"}) == []


def _doc(name, versions):
    return {"name": name, "dist-tags": {"latest": versions[-1]},
            "time": {v: f"2026-10-{i + 1:02d}T00:00:00.000Z" for i, v in enumerate(versions)},
            "versions": {v: {"name": name, "version": v, "dist": {"tarball": f"https://t/{name}/{v}"}} for v in versions}}


def test_references_hold_previous_version_and_the_original():
    pkg = pkg_of({"package.json": json.dumps({"name": "kiki-baileys"}), "lib/a.js": "x\nevil()\n"})
    archives = {"https://t/kiki-baileys/1.0.0": pkg_of({"lib/a.js": "x\n"}),
                "https://t/@whiskeysockets/baileys/6.0.0": pkg_of({"lib/a.js": "x\n"})}

    def handler(request):
        assert "baileys" in str(request.url)
        return httpx.Response(200, json=_doc("@whiskeysockets/baileys", ["6.0.0"]))

    refs = references_for(httpx.Client(transport=httpx.MockTransport(handler)), _doc("kiki-baileys", ["1.0.0", "1.1.0"]), "1.1.0",
                          pkg, POPULAR, lambda url: archives[url])
    assert [r.label for r in refs] == ["the previous version 1.0.0", "@whiskeysockets/baileys@6.0.0, which it appears to be copied from"]


def test_a_failed_download_costs_one_reference_not_the_investigation():
    def boom(url):
        raise OSError("gone")

    pkg = pkg_of({"package.json": "{}", "a.js": "x"})
    assert references_for(httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(404))),
                          _doc("p", ["1.0.0", "1.1.0"]), "1.1.0", pkg, POPULAR, boom) == []


def test_diff_excerpts_are_citable_and_bounded():
    new = pkg_of({f"f{i}.js": f"fetch('https://x{i}.example')\n" * 20 for i in range(400)})
    out = diff_excerpts(new, [Reference("the previous version 1.0.0", pkg_of({}))])
    assert out[0].excerpt_id == "D1" and out[0].kind == "diff" and "the previous version 1.0.0" in out[0].note
    assert sum(len(x) for e in out for x in e.lines) <= 4000
