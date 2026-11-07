"""Executor concorrente sobre uma lista de hosts."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Callable


def run_hosts(hosts: list[str], fn: Callable[[str], None],
              threads: int = 20) -> None:
    """Chama fn(host) em paralelo. Excecoes por host nao derrubam o lote."""
    def safe(host: str) -> None:
        try:
            fn(host)
        except Exception:  # noqa: BLE001 - erro por host e isolado
            pass

    workers = max(1, min(threads, len(hosts))) if hosts else 1
    with ThreadPoolExecutor(max_workers=workers) as ex:
        list(ex.map(safe, hosts))
