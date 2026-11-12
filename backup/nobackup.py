"""`not-backed-up`: what is NOT backed up, by size, from diskaudit.backup_coverage (INFRA-112).
Queries and formatting are pure functions; only `run` touches a database."""
from __future__ import annotations

from .config import BackupError

# one row per hardlinked file (host, inode) so a hardlink is not counted N times; inode-less rows stay as they are
_BASE = ("SELECT host, path, size_bytes FROM ("
         "(SELECT DISTINCT ON (host, inode) host, path, size_bytes FROM diskaudit.backup_coverage "
         "WHERE classification = 'NOT_BACKED_UP' AND inode IS NOT NULL{hw} ORDER BY host, inode, path) "
         "UNION ALL (SELECT host, path, size_bytes FROM diskaudit.backup_coverage "
         "WHERE classification = 'NOT_BACKED_UP' AND inode IS NULL{hw})) u")
_KEYS = {
    "type": "COALESCE(NULLIF(lower(substring(path from '\\.([^./]+)$')), ''), '(no extension)')",
    "folder": "COALESCE(substring(path from '^/[^/]+(?:/[^/]+){0,2}'), '/')",
}


def build_queries(host: str | None, by: str, limit: int) -> list[tuple[str, str, tuple]]:
    """[(label, sql, params)]: totals per host, then the top groups by bytes."""
    if by not in _KEYS:
        raise BackupError(f"--by must be one of {sorted(_KEYS)}")
    if limit < 1 or limit > 10000:
        raise BackupError("--limit must be between 1 and 10000")
    hw, params = ("", ()) if host is None else (" AND host = %s", (host,))
    base = _BASE.format(hw=hw)
    p2 = params * 2
    totals = (f"SELECT host, count(*), coalesce(sum(size_bytes), 0)::bigint FROM {base} GROUP BY host ORDER BY 3 DESC")
    groups = (f"SELECT {_KEYS[by]} AS grp, count(*), coalesce(sum(size_bytes), 0)::bigint FROM {base} "
              f"GROUP BY grp ORDER BY 3 DESC, grp LIMIT %s")
    return [("totals", totals, p2), ("groups", groups, p2 + (limit,))]


def _gb(b: int) -> str:
    return f"{b / 1e9:,.2f}"


def format_report(totals: list[tuple], groups: list[tuple], by: str, host: str | None) -> str:
    out = [f"NOT BACKED UP ({host or 'all hosts'}), hardlink-deduplicated", ""]
    if not totals:
        out.append("No NOT_BACKED_UP rows. (If classify has never run, there are no rows at all.)")
        return "\n".join(out)
    out += ["Host                files          GB"]
    out += [f"{h:<16} {n:>8,} {_gb(b):>12}" for h, n, b in totals]
    out += ["", f"Top {len(groups)} by {'folder (first 3 levels)' if by == 'folder' else 'file type'}:",
            f"{'GB':>12} {'files':>10}  {by}"]
    out += [f"{_gb(b):>12} {n:>10,}  {g}" for g, n, b in groups]
    return "\n".join(out)


def not_backed_up(host: str | None, by: str, limit: int, conn=None) -> int:
    from .coverage import connect
    qs = build_queries(host, by, limit)
    conn = conn or connect()
    try:
        cur = conn.cursor()
        res = {}
        for label, sql, params in qs:
            cur.execute(sql, params)
            res[label] = cur.fetchall()
    finally:
        conn.close()
    print(format_report(res["totals"], res["groups"], by, host))
    return 0
