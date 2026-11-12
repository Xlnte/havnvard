from __future__ import annotations

import csv
import io
import json
import os

from flask import Blueprint, Response, abort, jsonify, render_template, request
import psycopg
from psycopg.rows import dict_row

bp = Blueprint("infra126",__name__,template_folder="templates")


def _connect():
    return psycopg.connect(os.environ["POSTGRES_URL"],row_factory=dict_row)


@bp.get("/havnvard/verification-status")
def verification_status():
    min_age = request.args.get("min_hash_age_days",type=int)
    host = request.args.get("host")
    with _connect() as conn, conn.cursor() as cur:
        cur.execute("SELECT * FROM diskaudit.v_infra126_sla_status ORDER BY host,tier")
        slas = cur.fetchall()
        cur.execute(
            """
            SELECT host,path,file_key,size_bytes,first_hashed_at,current_baseline_at,last_verified_at,
                   days_since_last_verification,verification_count,baseline_revision_count,
                   hash_divergence_count,hash_status,is_critical
            FROM diskaudit.v_infra126_verification_age
            WHERE (%s IS NULL OR host=%s)
              AND (%s IS NULL OR last_verified_at IS NULL OR days_since_last_verification >= %s)
            ORDER BY days_since_last_verification DESC NULLS FIRST
            LIMIT 1000
            """,
            (host,host,min_age,min_age),
        )
        files = cur.fetchall()
        cur.execute(
            """
            SELECT file_key,host,path,mutable_score,decision_state,operator_action,
                   operator_verdict,last_seen_divergence_at,plane_ticket_id
            FROM diskaudit.corruption_suspects
            WHERE operator_verdict IS NULL OR operator_verdict NOT IN ('benign')
            ORDER BY last_seen_divergence_at DESC LIMIT 250
            """
        )
        suspects = cur.fetchall()
        conn.rollback()
    return render_template("verification_status.html",slas=slas,files=files,suspects=suspects,min_age=min_age,host=host)


@bp.get("/havnvard/verification-file/<file_key_value>")
def verification_file(file_key_value: str):
    if len(file_key_value) != 64:
        abort(404)
    with _connect() as conn, conn.cursor() as cur:
        cur.execute("SELECT * FROM diskaudit.v_infra126_verification_age WHERE file_key=%s",(file_key_value,))
        file_row = cur.fetchone()
        if not file_row:
            abort(404)
        cur.execute(
            """
            SELECT observed_at,run_id,result_state,baseline_hash,observed_hash,
                   observed_size,observed_mtime_ns,observed_inode
            FROM diskaudit.hash_observations
            WHERE file_key=%s ORDER BY observed_at DESC LIMIT 200
            """,
            (file_key_value,),
        )
        observations = cur.fetchall()
        cur.execute(
            """
            SELECT divergence_id,created_at,tier,old_hash,new_hash,mutable_score,
                   divergence_type,decision_state,odd_sources,operator_verdict
            FROM diskaudit.hash_divergences
            WHERE file_key=%s ORDER BY created_at DESC LIMIT 200
            """,
            (file_key_value,),
        )
        divergences = cur.fetchall()
        conn.rollback()
    return render_template("verification_file.html",file=file_row,observations=observations,divergences=divergences)


def _divergence_rows(limit: int = 10000):
    with _connect() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT d.file_key,d.host,d.path,d.tier,d.old_hash,d.new_hash,d.new_hashed_at,
                   v.current_baseline_at AS hashed_at,v.last_verified_at,
                   v.days_since_last_verification AS hash_age_days,v.hash_status,
                   d.mutable_score,d.divergence_type,d.decision_state,d.operator_verdict,
                   count(*) OVER (PARTITION BY d.file_key) AS divergence_count_4w
            FROM diskaudit.hash_divergences d
            LEFT JOIN diskaudit.v_infra126_verification_age v ON v.file_key=d.file_key
            WHERE d.created_at >= now()-interval '4 weeks'
            ORDER BY d.created_at DESC LIMIT %s
            """,
            (limit,),
        )
        rows = cur.fetchall()
        conn.rollback()
        return rows


@bp.get("/havnvard/verification-divergences.csv")
def divergence_csv():
    output = io.StringIO()
    rows = _divergence_rows()
    columns = [
        "file_key","host","path","tier","old_hash","new_hash","new_hashed_at",
        "hashed_at","last_verified_at","hash_age_days","hash_status","mutable_score",
        "divergence_type","decision_state","operator_verdict","divergence_count_4w",
    ]
    writer = csv.DictWriter(output,fieldnames=columns)
    writer.writeheader()
    writer.writerows(rows)
    return Response(output.getvalue(),mimetype="text/csv",headers={"Content-Disposition":"attachment; filename=infra126-divergences.csv"})


@bp.get("/havnvard/verification-divergences.json")
def divergence_json():
    rows = _divergence_rows()
    return Response(json.dumps(rows,default=str),mimetype="application/json")
