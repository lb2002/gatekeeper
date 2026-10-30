from gatekeeper.triage.campaign import matches, specific_iocs


def test_only_attacker_specific_endpoints_are_kept():
    text = """
    https.request("https://130.162.231.177:8443/", opts)
    fetch("https://webhook.site/d730a68c-27bd-4bb5-b1b9-d57a0a4b17ac/semz")
    get("https://nobody-johnston-with-enabling.trycloudflare.com/aa?x=1")
    see https://github.com/foo/bar and https://webhook.site/ and http://127.0.0.1:8099/collect
    const local = "10.0.0.5"; const dns = "8.8.8.8"; fetch("http://1.1.1.1/"); version = "1.2.3.4"
    """
    assert specific_iocs(text) == {
        "130.162.231.177",
        "webhook.site/d730a68c-27bd-4bb5-b1b9-d57a0a4b17ac",
        "nobody-johnston-with-enabling.trycloudflare.com",
    }


def test_a_reupload_with_the_same_collector_matches_its_source():
    known = {"130.162.231.177": "@pcb-dp/qa-commons@1.0.10"}
    text = 'https.request("https://130.162.231.177:8443/", {method: "POST"})'
    assert matches(text, known) == [("130.162.231.177", "@pcb-dp/qa-commons@1.0.10")]
    assert matches("nothing here", known) == []


def test_shared_path_words_are_not_tokens():
    text = ('get("https://cdn.discordapp.com/attachments/1029384756/abc.png"); '
            'post("https://discord.com/api/webhooks/1234567890123/AbC-dEf_9")')
    assert specific_iocs(text) == {"cdn.discordapp.com/1029384756", "discord.com/1234567890123"}
