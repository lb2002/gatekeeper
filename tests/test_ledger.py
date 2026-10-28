from gatekeeper.ledger import canonical_line, commitment, new_salt, verify


def test_commitment_hides_the_package_and_verifies_with_the_salt():
    line = canonical_line("evil-pkg", "1.0.0", "2026-10-28T06:58:06Z", "malicious")
    salt = new_salt()
    digest = commitment(salt, line)
    assert "evil-pkg" not in digest and len(digest) == 64
    assert verify(salt, line, digest)
    assert not verify(new_salt(), line, digest)
    assert not verify(salt, canonical_line("evil-pkg", "1.0.1", "2026-10-28T06:58:06Z", "malicious"), digest)


def test_ots_proof_has_header_digest_and_calendar_answer(monkeypatch):
    import hashlib

    import httpx

    from gatekeeper import ledger

    class Resp:
        content = b"calendar-timestamp-bytes"

        def raise_for_status(self):
            pass

    sent = {}

    def fake_post(url, content, **kw):
        sent["url"], sent["digest"] = url, content
        return Resp()

    monkeypatch.setattr(httpx, "post", fake_post)
    proof = ledger.ots_stamp(b"batch")
    digest = hashlib.sha256(b"batch").digest()
    assert sent["digest"] == digest and sent["url"].endswith("/digest")
    assert proof == ledger.OTS_HEADER + digest + b"calendar-timestamp-bytes"
