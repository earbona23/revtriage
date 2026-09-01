"""IOC extraction: precision on the noisy types, provenance on all of them."""

from __future__ import annotations

from revtriage import iocs


def _types(indicators):
    return {i.type for i in indicators}


def test_extracts_url_and_its_host():
    found = iocs.extract([("L0", "connect to http://malware.example/beacon?id=1 now")])
    values = {(i.type, i.value) for i in found}
    assert ("url", "http://malware.example/beacon?id=1") in values
    assert ("domain", "malware.example") in values


def test_ipv4_validates_octets():
    found = iocs.extract([("L0", "good 203.0.113.9 bad 999.1.2.3 version 1.2.3.4.5")])
    ips = {i.value for i in found if i.type == "ipv4"}
    assert "203.0.113.9" in ips
    assert "999.1.2.3" not in ips


def test_registry_key_extracted():
    found = iocs.extract([("L0", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Updater")])
    assert any(i.type == "registry_key" for i in found)


def test_standalone_filename_is_not_a_domain():
    """kernel32.dll and schtasks.exe must never appear as domains."""
    found = iocs.extract([("L0", "loads kernel32.dll then runs schtasks.exe quietly")])
    domains = {i.value for i in found if i.type == "domain"}
    assert "kernel32.dll" not in domains
    assert "schtasks.exe" not in domains


def test_standalone_real_domain_is_accepted():
    found = iocs.extract([("L0", "beacon to evil-c2.top every minute")])
    assert any(i.type == "domain" and i.value == "evil-c2.top" for i in found)


def test_provenance_records_the_layer():
    found = iocs.extract([("L0", "clean"), ("L3", "http://malware.example/x")])
    urls = [i for i in found if i.type == "url"]
    assert urls and urls[0].layer == "L3"


def test_dedup_across_layers_keeps_first_seen():
    found = iocs.extract([("L1", "http://a.example/x"), ("L2", "http://a.example/x")])
    urls = [i for i in found if i.type == "url"]
    assert len(urls) == 1
    assert urls[0].layer == "L1"


def test_defang_is_display_only():
    assert iocs.defang("http://a.example") == "hxxp://a[.]example"
