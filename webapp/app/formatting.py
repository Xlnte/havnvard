"""Shared display-formatting helpers used by all three HavnVard UI views."""
from __future__ import annotations


def human_bytes(n: int | None) -> str:
    if n is None:
        return "—"
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if abs(n) < 1024.0:
            return f"{n:,.1f} {unit}" if unit != "B" else f"{int(n):,} B"
        n /= 1024.0
    return f"{n:,.1f} EB"


def human_count(n: int | None) -> str:
    return "—" if n is None else f"{n:,}"
