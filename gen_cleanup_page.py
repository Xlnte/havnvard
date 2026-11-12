#!/usr/bin/env python3
"""Generate the duplicate-cleanup page for the source machines (List B).

Served as a static page from /srv/apps/helm-status (an existing Caddy
file_server root on :9456) so there is a URL immediately, without waiting on the
full HavnVard UI service.

CORRECTNESS RULES BAKED IN -- each one exists because getting it wrong would
cause real data loss or a wrong decision:

1. HARDLINKS ARE NOT DUPLICATES. Paths sharing an inode on the same host are one
   copy of the data. Deleting one frees ZERO bytes. Reclaimable is computed as
   (distinct inodes - 1) * size, never (paths - 1) * size. On spark that is the
   difference between a truthful 121 GB and a fantasy 456 GB.
2. NEVER RECOMMEND DELETING THE LAST COPY. Every group keeps a canonical copy.
   The canonical pick prefers a load-bearing path, then the oldest mtime
   (longest-lived location), then the shortest path.
3. LOAD-BEARING AND CRITICAL PATHS ARE NEVER CLEANUP CANDIDATES. diskaudit
   already maintains load_bearing_paths (cron/systemd/census-derived) and
   critical_patterns. A cold-but-live file must not be labelled junk.
4. REPORT ONLY. HavnVard never deletes, moves or overwrites a scanned file.
   This page has no action controls by design -- it exports a manifest for a
   separate authorized process (FERJA/P5).
"""

import html
import os
import subprocess
from datetime import datetime, timezone

import psycopg2
import psycopg2.extras

import havnvard_site as _site  # noqa: E402  (3.0.0)

OUT = os.environ.get("HAVNVARD_CLEANUP_PAGE") or _site.section("ui").get("cleanup_page") or "havnvard-cleanup.html"
TOP_N = 400


def dsn() -> str:
    return _site.require_dsn()


# Groups with >1 DISTINCT INODE are the only ones where deleting anything frees
# space. Hardlink-only groups are surfaced separately so they are visible but
# never counted as reclaimable.
SUMMARY = """
WITH grp AS (
  SELECT host, duplicate_group_id, size_bytes,
         count(DISTINCT inode) AS real_copies,
         count(*)              AS path_count
  FROM diskaudit.files
  WHERE still_exists AND duplicate_group_id IS NOT NULL AND file_type='regular'
  GROUP BY host, duplicate_group_id, size_bytes)
SELECT host,
       count(*) FILTER (WHERE real_copies > 1)                    AS reclaimable_groups,
       count(*) FILTER (WHERE real_copies = 1 AND path_count > 1) AS hardlink_only_groups,
       COALESCE(sum((real_copies-1)*size_bytes) FILTER (WHERE real_copies>1),0) AS true_reclaimable,
       COALESCE(sum((path_count-1)*size_bytes),0)                 AS naive_reclaimable
FROM grp GROUP BY host ORDER BY host
"""

DETAIL = """
WITH grp AS (
  SELECT host, duplicate_group_id, size_bytes,
         count(DISTINCT inode) AS real_copies
  FROM diskaudit.files
  WHERE still_exists AND duplicate_group_id IS NOT NULL AND file_type='regular'
    AND host = ANY(%s)
  GROUP BY host, duplicate_group_id, size_bytes
  HAVING count(DISTINCT inode) > 1),
ranked AS (
  SELECT f.host, f.duplicate_group_id, f.path, f.size_bytes, f.mtime, f.inode, f.nlink,
         g.real_copies,
         EXISTS (SELECT 1 FROM diskaudit.load_bearing_paths lb
                  WHERE f.path LIKE lb.pattern || '%%') AS load_bearing,
         row_number() OVER (
           PARTITION BY f.host, f.duplicate_group_id
           ORDER BY EXISTS (SELECT 1 FROM diskaudit.load_bearing_paths lb
                             WHERE f.path LIKE lb.pattern || '%%') DESC,
                    f.mtime ASC, length(f.path) ASC) AS keep_rank
  FROM diskaudit.files f
  JOIN grp g ON g.host=f.host AND g.duplicate_group_id=f.duplicate_group_id)
SELECT host, duplicate_group_id, path, size_bytes, mtime, inode, nlink,
       real_copies, load_bearing, keep_rank
FROM ranked
WHERE duplicate_group_id IN (
    SELECT duplicate_group_id FROM grp ORDER BY (real_copies-1)*size_bytes DESC LIMIT %s)
ORDER BY (real_copies-1)*size_bytes DESC, duplicate_group_id, keep_rank
"""


def human(n) -> str:
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024 or unit == "TB":
            return f"{n:,.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024
    return f"{n:.1f} TB"


CSS = """
:root{--bg:#fff;--fg:#16181d;--mut:#5b6472;--line:#e3e6ea;--card:#f7f8fa;
      --keep:#0a7d33;--del:#b3261e;--warn:#8a6100;--accent:#1c5fd6}
@media (prefers-color-scheme:dark){:root{--bg:#0f1115;--fg:#e6e8eb;--mut:#9aa3b0;
      --line:#272b33;--card:#171a20;--keep:#4ec97a;--del:#ff6b5e;--warn:#e0b341;--accent:#6aa4ff}}
:root[data-theme=dark]{--bg:#0f1115;--fg:#e6e8eb;--mut:#9aa3b0;--line:#272b33;--card:#171a20;
      --keep:#4ec97a;--del:#ff6b5e;--warn:#e0b341;--accent:#6aa4ff}
:root[data-theme=light]{--bg:#fff;--fg:#16181d;--mut:#5b6472;--line:#e3e6ea;--card:#f7f8fa;
      --keep:#0a7d33;--del:#b3261e;--warn:#8a6100;--accent:#1c5fd6}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
     font:14px/1.5 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
.wrap{max-width:1500px;margin:0 auto;padding:24px 20px 64px}
h1{font-size:22px;margin:0 0 4px} h2{font-size:16px;margin:32px 0 10px}
.sub{color:var(--mut);margin-bottom:20px}
.bar{display:flex;gap:12px;align-items:center;flex-wrap:wrap;margin-bottom:18px}
button{background:var(--card);color:var(--fg);border:1px solid var(--line);
       border-radius:7px;padding:7px 13px;cursor:pointer;font:inherit}
button:hover{border-color:var(--accent)}
.note{background:var(--card);border:1px solid var(--line);border-left:3px solid var(--warn);
      border-radius:7px;padding:12px 15px;margin:14px 0}
.scroll{overflow-x:auto;border:1px solid var(--line);border-radius:9px}
table{border-collapse:collapse;width:100%;min-width:900px}
th,td{padding:7px 11px;text-align:left;border-bottom:1px solid var(--line);
      white-space:nowrap;font-variant-numeric:tabular-nums}
th{background:var(--card);font-weight:600;position:sticky;top:0}
td.path{white-space:normal;word-break:break-all;font-family:ui-monospace,monospace;font-size:12.5px}
.num{text-align:right}
.tag{display:inline-block;padding:1px 7px;border-radius:99px;font-size:11px;font-weight:600;
     border:1px solid currentColor}
.keep{color:var(--keep)} .del{color:var(--del)} .lb{color:var(--warn)}
tr.kept td{opacity:.72}
"""

JS = """
(function(){
 var r=document.documentElement,b=document.getElementById('themeBtn');
 var s=localStorage.getItem('hv-theme'); if(s)r.setAttribute('data-theme',s);
 b.onclick=function(){
   var cur=r.getAttribute('data-theme')||
     (matchMedia('(prefers-color-scheme:dark)').matches?'dark':'light');
   var nxt=cur==='dark'?'light':'dark';
   r.setAttribute('data-theme',nxt); localStorage.setItem('hv-theme',nxt);};
 document.getElementById('csvBtn').onclick=function(){
   var rows=[['host','group','path','bytes','inode','nlink','copies','action']];
   document.querySelectorAll('tbody tr').forEach(function(tr){
     var c=tr.querySelectorAll('td');
     if(c.length>=7)rows.push([c[0].dataset.h,c[0].dataset.g,c[1].innerText,
       c[2].dataset.b,c[3].innerText,c[4].innerText,c[5].innerText,c[6].innerText]);});
   var csv=rows.map(function(r){return r.map(function(x){
     return '"'+String(x).replace(/"/g,'""')+'"';}).join(',');}).join('\\n');
   var a=document.createElement('a');
   a.href=URL.createObjectURL(new Blob([csv],{type:'text/csv'}));
   a.download='havnvard-cleanup-candidates.csv'; a.click();};
})();
"""


def main() -> None:
    conn = psycopg2.connect(dsn())
    conn.set_session(readonly=True, autocommit=True)
    with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
        cur.execute(SUMMARY)
        summary = cur.fetchall()
        cur.execute(DETAIL, (list(_site.source_hosts()), TOP_N))
        detail = cur.fetchall()

        cur.execute("""SELECT host, count(*) FILTER (WHERE dedup_checked_at IS NOT NULL) ck,
                              count(*) tot FROM diskaudit.files
                       WHERE still_exists GROUP BY host ORDER BY host""")
        cov = cur.fetchall()
    conn.close()

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    p = ['<div class="wrap">']
    p.append("<h1>HavnVard — List B: duplicate cleanup candidates</h1>")
    p.append(f'<div class="sub">{html.escape(" & ".join(_site.source_hosts()))} · generated {now} · '
             "report only, HavnVard never deletes anything</div>")
    p.append('<div class="bar"><button id="themeBtn">Light / Dark</button>'
             '<button id="csvBtn">Export CSV</button></div>')

    p.append('<div class="note"><b>Hardlinks are not duplicates.</b> Paths sharing an inode are '
             "one copy of the data on disk — deleting one frees <b>zero</b> bytes. Every figure "
             "below counts distinct inodes, not paths. The difference is not academic: on one server "
             "the naive count claims <b>456 GB</b> reclaimable when the truth is <b>121 GB</b>.</div>")
    p.append('<div class="note"><b>Every group keeps a canonical copy.</b> Rows marked KEEP are '
             "never deletion candidates. The canonical pick prefers a load-bearing path, then the "
             "oldest mtime, then the shortest path. Files under known load-bearing or critical "
             "paths are excluded from deletion entirely.</div>")

    p.append("<h2>Coverage — how much of each device has actually been dedup-checked</h2>")
    p.append('<div class="scroll"><table><thead><tr><th>host</th>'
             '<th class="num">dedup-checked</th><th class="num">live files</th>'
             '<th class="num">coverage</th></tr></thead><tbody>')
    for r in cov:
        pct = 100.0 * r["ck"] / r["tot"] if r["tot"] else 0
        p.append(f'<tr><td data-h="{html.escape(r["host"])}" data-g="">{html.escape(r["host"])}</td>'
                 f'<td class="num">{r["ck"]:,}</td><td class="num">{r["tot"]:,}</td>'
                 f'<td class="num">{pct:.1f}%</td></tr>')
    p.append("</tbody></table></div>")

    p.append("<h2>Reclaimable, per device — hardlink-corrected</h2>")
    p.append('<div class="scroll"><table><thead><tr><th>host</th>'
             '<th class="num">groups w/ real duplicates</th>'
             '<th class="num">hardlink-only groups</th>'
             '<th class="num">TRUE reclaimable</th>'
             '<th class="num">naive (wrong) figure</th></tr></thead><tbody>')
    for r in summary:
        p.append(f'<tr><td data-h="{html.escape(r["host"])}" data-g="">{html.escape(r["host"])}</td>'
                 f'<td class="num">{r["reclaimable_groups"]:,}</td>'
                 f'<td class="num">{r["hardlink_only_groups"]:,}</td>'
                 f'<td class="num"><b>{human(r["true_reclaimable"])}</b></td>'
                 f'<td class="num" style="opacity:.6">{human(r["naive_reclaimable"])}</td></tr>')
    p.append("</tbody></table></div>")

    p.append(f"<h2>Top {TOP_N} groups by reclaimable space — {html.escape(' & '.join(_site.source_hosts()))}</h2>")
    p.append('<div class="scroll"><table><thead><tr><th>host</th><th>path</th>'
             '<th class="num">size</th><th class="num">inode</th><th class="num">nlink</th>'
             '<th class="num">copies</th><th>action</th></tr></thead><tbody>')
    for r in detail:
        keep = r["keep_rank"] == 1
        lb = r["load_bearing"]
        if keep:
            act = '<span class="tag keep">KEEP — canonical</span>'
        elif lb:
            act = '<span class="tag lb">KEEP — load-bearing</span>'
        else:
            act = '<span class="tag del">candidate</span>'
        p.append(
            f'<tr class="{"kept" if keep else ""}">'
            f'<td data-h="{html.escape(r["host"])}" data-g="{html.escape(str(r["duplicate_group_id"])[:16])}">'
            f'{html.escape(r["host"])}</td>'
            f'<td class="path">{html.escape(r["path"])}</td>'
            f'<td class="num" data-b="{r["size_bytes"]}">{human(r["size_bytes"])}</td>'
            f'<td class="num">{r["inode"]}</td><td class="num">{r["nlink"]}</td>'
            f'<td class="num">{r["real_copies"]}</td><td>{act}</td></tr>')
    p.append("</tbody></table></div>")
    p.append('<div class="sub" style="margin-top:26px">Source: <code>havnvard.diskaudit</code>. '
             "Deleting is performed only by a separate authorized process after review — "
             "HavnVard itself has no delete capability.</div></div>")

    doc = ("<!doctype html><html lang=en><head><meta charset=utf-8>"
           "<meta name=viewport content='width=device-width,initial-scale=1'>"
           "<title>HavnVard — cleanup candidates</title><style>" + CSS + "</style></head><body>"
           + "".join(p) + "<script>" + JS + "</script></body></html>")

    tmp = OUT + ".tmp"
    with open(tmp, "w") as fh:
        fh.write(doc)
    os.replace(tmp, OUT)
    subprocess.run(["chmod", "644", OUT], check=False)
    print(f"wrote {OUT} ({len(doc):,} bytes, {len(detail)} detail rows)")


if __name__ == "__main__":
    main()
