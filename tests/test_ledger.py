from gatekeeper.ledger import canonical_line, commitment, new_salt, verify


def test_commitment_hides_the_package_and_verifies_with_the_salt():
    line = canonical_line("evil-pkg", "1.0.0", "2026-10-28T06:58:06Z", "malicious")
    salt = new_salt()
    digest = commitment(salt, line)
    assert "evil-pkg" not in digest and len(digest) == 64
    assert verify(salt, line, digest)
    assert not verify(new_salt(), line, digest)
    assert not verify(salt, canonical_line("evil-pkg", "1.0.1", "2026-10-28T06:58:06Z", "malicious"), digest)
