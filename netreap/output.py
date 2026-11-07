"""Saida console (colorida, estilo CME) + JSON-lines opcional."""

from __future__ import annotations

import json
import sys
import threading

RESET = "\033[0m"
BOLD = "\033[1m"
_COLORS = {
    "info": "\033[36m",   # ciano  [*]
    "good": "\033[32m",   # verde  [+]
    "bad":  "\033[31m",   # vermelho [-]
    "warn": "\033[33m",   # amarelo [!]
}
_TAGS = {"info": "*", "good": "+", "bad": "-", "warn": "!"}


class Output:
    def __init__(self, json_path: str | None = None, no_color: bool = False):
        self._lock = threading.Lock()
        self._json = open(json_path, "w", encoding="utf-8") if json_path else None
        self.no_color = no_color or not sys.stdout.isatty()

    def _paint(self, level: str, text: str) -> str:
        if self.no_color:
            return text
        return f"{_COLORS.get(level, '')}{text}{RESET}"

    def event(self, proto: str, host: str, level: str, msg: str,
              port: int = 445, name: str = "", **fields) -> None:
        """Imprime uma linha e, se habilitado, grava o registro em JSON."""
        tag = self._paint(level, f"[{_TAGS.get(level, '*')}]")
        prefix = f"{proto:<5} {host:<15} {str(port):<5} {name:<16}"
        with self._lock:
            print(f"{prefix} {tag} {msg}")
            if self._json:
                record = {"proto": proto, "host": host, "port": port,
                          "name": name, "level": level, "msg": msg, **fields}
                self._json.write(json.dumps(record, ensure_ascii=False) + "\n")
                self._json.flush()

    def banner(self, text: str) -> None:
        with self._lock:
            print(text if self.no_color else f"{BOLD}{text}{RESET}")

    def close(self) -> None:
        if self._json:
            self._json.close()
            self._json = None
