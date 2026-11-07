"""Parsing e representacao de credenciais (senha ou hash NTLM / PtH)."""

from __future__ import annotations

import re
from dataclasses import dataclass

EMPTY_LM = "aad3b435b51404eeaad3b435b51404ee"
_HEX32 = re.compile(r"[0-9a-fA-F]{32}")


def parse_hash(h: str) -> tuple[str, str]:
    """Aceita 'LM:NT', ':NT' ou 'NT' e devolve (lmhash, nthash) minusculos.

    Se so houver o NT, usa o LM vazio padrao (necessario para pass-the-hash).
    """
    h = h.strip()
    if ":" in h:
        lm, nt = h.split(":", 1)
    else:
        lm, nt = "", h
    for part in (lm, nt):
        if part and not _HEX32.fullmatch(part):
            raise ValueError(f"hash NTLM invalido: {part!r}")
    if nt and not lm:
        lm = EMPTY_LM
    return lm.lower(), nt.lower()


@dataclass
class Credential:
    username: str
    password: str = ""
    domain: str = "."
    lmhash: str = ""
    nthash: str = ""

    @classmethod
    def make(cls, username: str, password: str | None = None,
             ntlm: str | None = None, domain: str = ".") -> "Credential":
        lm = nt = ""
        pw = password or ""
        if ntlm:
            lm, nt = parse_hash(ntlm)
            pw = ""
        return cls(username=username, password=pw, domain=domain,
                   lmhash=lm, nthash=nt)

    @property
    def uses_hash(self) -> bool:
        return bool(self.nthash)

    @property
    def secret(self) -> str:
        """Valor usado para autenticar (senha ou 'lm:nt')."""
        return f"{self.lmhash}:{self.nthash}" if self.uses_hash else self.password

    def label(self) -> str:
        dom = "" if self.domain in ("", ".") else self.domain
        who = f"{dom}\\{self.username}" if dom else self.username
        return f"{who}:{'<hash>' if self.uses_hash else self.password}"
