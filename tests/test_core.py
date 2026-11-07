"""Testes das partes puras (nao dependem de rede/AD)."""

import pytest

from netreap.creds import Credential, parse_hash, EMPTY_LM
from netreap.targets import expand_targets, _expand_one
from netreap.protocols.ldap import base_dn


def test_parse_hash_nt_only():
    lm, nt = parse_hash("31d6cfe0d16ae931b73c59d7e0c089c0")
    assert lm == EMPTY_LM
    assert nt == "31d6cfe0d16ae931b73c59d7e0c089c0"


def test_parse_hash_lm_nt():
    lm, nt = parse_hash("aad3b435b51404eeaad3b435b51404ee:"
                        "31d6cfe0d16ae931b73c59d7e0c089c0")
    assert lm == "aad3b435b51404eeaad3b435b51404ee"
    assert nt == "31d6cfe0d16ae931b73c59d7e0c089c0"


def test_parse_hash_invalid():
    with pytest.raises(ValueError):
        parse_hash("naoehhex")


def test_credential_pth_vs_pass():
    c1 = Credential.make("admin", password="P@ss", domain="CORP")
    assert not c1.uses_hash and c1.secret == "P@ss"
    c2 = Credential.make("admin", ntlm="31d6cfe0d16ae931b73c59d7e0c089c0")
    assert c2.uses_hash and c2.secret.endswith("089c0")
    assert "<hash>" in c2.label()


def test_expand_cidr():
    hosts = _expand_one("10.0.0.0/30")
    assert hosts == ["10.0.0.1", "10.0.0.2"]


def test_expand_range():
    hosts = _expand_one("192.168.1.10-12")
    assert hosts == ["192.168.1.10", "192.168.1.11", "192.168.1.12"]


def test_expand_dedup_and_host():
    hosts = expand_targets(["10.0.0.1", "10.0.0.1", "dc01.corp.local"])
    assert hosts == ["10.0.0.1", "dc01.corp.local"]


def test_expand_targets_file(tmp_path):
    f = tmp_path / "t.txt"
    f.write_text("# comentario\n10.0.0.5\n10.0.0.0/31\n")
    hosts = expand_targets([str(f)])
    assert "10.0.0.5" in hosts and "10.0.0.0" in hosts


def test_base_dn():
    assert base_dn("corp.local") == "DC=corp,DC=local"
