"""GuardedConn -- the DB seatbelt for nas_trigkey_dedup tests (HV-REQ-31).

Two independent protections, so a test can never write a real host's rows:

  1. REDIRECT: every SQL statement has the literal schema prefix `diskaudit.`
     rewritten to the session's THROWAWAY schema (conftest `nd_schema`, a copy
     of the live table shapes with the 1.4.0 migration applied). The code under
     test therefore physically cannot touch production tables through this
     connection -- it needs no knowledge of the redirect.
  2. REFUSE: any write (UPDATE/INSERT/DELETE/COPY/...) whose bound parameters
     (recursively) or SQL text name a real host is refused with
     RealHostWriteRefused, even though (1) already makes it harmless. A test
     that drifts toward a real host fails loudly instead of "passing".
"""
from __future__ import annotations

import re

REAL_HOSTS = frozenset({"nas-1", "agent-1", "server-1", "laptop-2", "laptop-3", "desktop-1", "desktop-2"})  # tests/site.test.toml hosts + spares
_WRITE_RE = re.compile(r"^\s*(UPDATE|INSERT|DELETE|COPY|MERGE|TRUNCATE)\b", re.I)


class RealHostWriteRefused(AssertionError):
    pass


def _strings(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield from _strings(k)
            yield from _strings(v)
    elif isinstance(obj, (list, tuple, set, frozenset)):
        for v in obj:
            yield from _strings(v)


def check_write(sql: str, params) -> None:
    if not _WRITE_RE.match(sql):
        return
    for lit in REAL_HOSTS:
        if f"'{lit}'" in sql:
            raise RealHostWriteRefused(f"write statement names real host literal {lit!r}: {sql[:120]!r}")
    for s in _strings(params):
        if s in REAL_HOSTS:
            raise RealHostWriteRefused(f"write statement binds real host {s!r}: {sql[:120]!r}")


class GuardedCursor:
    def __init__(self, cur, conn):
        self._cur, self._conn = cur, conn

    def _rewrite(self, sql):
        return sql.replace("diskaudit.", self._conn.schema + ".") if isinstance(sql, str) else sql

    def execute(self, query, params=None, **kw):
        check_write(query, params)
        self._cur.execute(self._rewrite(query), params, **kw)
        return self

    def executemany(self, query, params_seq, **kw):
        params_seq = list(params_seq)
        for p in params_seq:
            check_write(query, p)
        self._cur.executemany(self._rewrite(query), params_seq, **kw)
        return self

    def copy(self, statement, *a, **kw):
        check_write(statement, None)
        return self._cur.copy(self._rewrite(statement), *a, **kw)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self._cur.close()
        return False

    def __iter__(self):
        return iter(self._cur)

    def __getattr__(self, name):
        return getattr(self._cur, name)


class GuardedConn:
    def __init__(self, conn, schema: str):
        assert schema != "diskaudit" and schema.startswith("diskaudit_t_"), schema
        self._conn, self.schema = conn, schema

    def cursor(self, *a, **kw):
        return GuardedCursor(self._conn.cursor(*a, **kw), self)

    def __getattr__(self, name):
        return getattr(self._conn, name)
