"""Plain-text email from the hub (3.3.0): the force-open email to the user. OFF unless configured.

backup.toml:
    [mail]
    host = "smtp.example.com"
    port = 587                  # 465 with ssl = true
    starttls = true             # default true on port 587
    ssl = false
    user = "hub@example.com"    # optional (no login when absent)
    password_file = "~/.config/havnvard/smtp.pass"
    from = "HavnVard <hub@example.com>"

`send` never raises and never stays silent: it returns "sent", "not configured" or "failed: ERROR", and the caller
records that in the audit log and shows it to the admin. Standard library only (smtplib); the password is read from
its file at send time and never printed.
"""
from __future__ import annotations

import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from pathlib import Path

from . import config

TIMEOUT_S = 20


def settings(cfg: dict | None = None) -> dict | None:
    m = (cfg if cfg is not None else config.load()).get("mail") or {}
    if not m.get("host") or not m.get("from"):
        return None
    return m


def send(to: str, subject: str, body: str, cfg: dict | None = None, smtp=None) -> str:
    try:
        m = settings(cfg)
    except (OSError, ValueError, config.BackupError) as e:   # a broken config file is a visible status, not a crash
        return f"failed: cannot read the mail settings: {e}"[:300]
    if m is None:
        return "not configured"
    port = int(m.get("port") or (465 if m.get("ssl") else 587))
    use_ssl = bool(m.get("ssl"))
    starttls = m.get("starttls", not use_ssl and port != 25)
    try:
        msg = EmailMessage()                      # a CR/LF in an address raises ValueError here: a status, not a crash
        msg["From"], msg["To"], msg["Subject"] = m["from"], to, subject
        msg["Date"], msg["Message-ID"] = formatdate(localtime=True), make_msgid(domain="havnvard")
        msg.set_content(body)
        password = None
        if m.get("user"):
            password = Path(str(m.get("password_file") or "")).expanduser().read_text().strip()
        ctx = ssl.create_default_context()
        if smtp is None:
            smtp = smtplib.SMTP_SSL if use_ssl else smtplib.SMTP
        kw = {"context": ctx} if use_ssl and smtp is smtplib.SMTP_SSL else {}
        with smtp(m["host"], port, timeout=TIMEOUT_S, **kw) as s:
            if starttls and not use_ssl:
                s.starttls(context=ctx)
            if m.get("user"):
                s.login(m["user"], password)
            s.send_message(msg)
    except (OSError, smtplib.SMTPException, ValueError) as e:
        return f"failed: {type(e).__name__}: {e}"[:300]
    return "sent"
