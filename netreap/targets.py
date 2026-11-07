"""Expansao de alvos: IP, CIDR, faixa, hostname e arquivos."""

from __future__ import annotations

import ipaddress
import os


def _expand_one(spec: str) -> list[str]:
    spec = spec.strip()
    if not spec:
        return []

    # CIDR -> hosts
    if "/" in spec:
        try:
            net = ipaddress.ip_network(spec, strict=False)
            if net.num_addresses <= 2:
                return [str(net.network_address)]
            return [str(ip) for ip in net.hosts()]
        except ValueError:
            return [spec]

    # faixa: 10.0.0.1-50  ou  10.0.0.1-10.0.0.50
    if "-" in spec and spec.count(".") >= 3:
        base, end = spec.rsplit("-", 1)
        try:
            start = ipaddress.ip_address(base)
            if "." in end:
                last = ipaddress.ip_address(end)
            else:
                prefix = base.rsplit(".", 1)[0]
                last = ipaddress.ip_address(f"{prefix}.{end}")
            lo, hi = sorted((int(start), int(last)))
            return [str(ipaddress.ip_address(i)) for i in range(lo, hi + 1)]
        except ValueError:
            return [spec]

    return [spec]


def expand_targets(specs: list[str]) -> list[str]:
    """Expande uma lista de especificacoes de alvo, deduplicando e
    preservando a ordem. Um item '@arquivo' (ou um arquivo existente) e
    lido linha a linha."""
    out: list[str] = []
    seen: set[str] = set()

    def add(host: str) -> None:
        if host and host not in seen:
            seen.add(host)
            out.append(host)

    for spec in specs:
        is_file = spec.startswith("@") or os.path.isfile(spec)
        if is_file:
            path = spec[1:] if spec.startswith("@") else spec
            with open(path, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        for host in _expand_one(line):
                            add(host)
        else:
            for host in _expand_one(spec):
                add(host)
    return out
