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

3.3.6: (INFRA-605) a login (AUTH) is only ever attempted over TLS: `ssl = true`, or STARTTLS that succeeded; a configuration
with a user and neither is refused, never sent in cleartext. `ssl` / `starttls` are parsed strictly: true/false, yes/no, on/off,
1/0 (any case); the string "false" is false, and anything else is a configuration error shown as `failed: ...`.
(INFRA-606) The hub web server is single-threaded, so it never talks SMTP inside a request: `OUTBOX.submit` puts the message on
a bounded queue and a background worker sends it; the outcome is counted (`OUTBOX.stats`) and handed to the caller's
`on_done` (the hub writes it to the audit log). A full queue is a visible `failed: ...`, never a silent drop.
"""
from __future__ import annotations

import logging
import queue
import smtplib
import ssl
import threading
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from pathlib import Path

from . import config

TIMEOUT_S = 20
QUEUE_MAX = 50
log = logging.getLogger("havnvard.mail")

_TRUE, _FALSE = {"true", "yes", "on", "1"}, {"false", "no", "off", "0"}


def parse_bool(v, name: str) -> bool:
    """Strict boolean from the config: a real bool, 0/1, or true/false/yes/no/on/off in any case. Anything else is an error."""
    if isinstance(v, bool):
        return v
    if isinstance(v, int) and v in (0, 1):
        return bool(v)
    if isinstance(v, str) and v.strip().lower() in _TRUE | _FALSE:
        return v.strip().lower() in _TRUE
    raise ValueError(f"[mail] {name} must be true or false, got {v!r}")


def settings(cfg: dict | None = None) -> dict | None:
    m = (cfg if cfg is not None else config.load()).get("mail") or {}
    if not m.get("host") or not m.get("from"):
        return None
    return m


def settings_or_none(cfg: dict | None = None) -> dict | None:
    """`settings`, but a broken config file counts as configured (so the failure is reported by `send`, not hidden)."""
    try:
        return settings(cfg)
    except (OSError, ValueError, config.BackupError):
        return {}


def send(to: str, subject: str, body: str, cfg: dict | None = None, smtp=None) -> str:
    try:
        m = settings(cfg)
    except (OSError, ValueError, config.BackupError) as e:   # a broken config file is a visible status, not a crash
        return f"failed: cannot read the mail settings: {e}"[:300]
    if m is None:
        return "not configured"
    try:
        use_ssl = parse_bool(m.get("ssl", False), "ssl")
        port = int(m.get("port") or (465 if use_ssl else 587))
        starttls = parse_bool(m["starttls"], "starttls") if "starttls" in m else (not use_ssl and port != 25)
        if m.get("user") and not (use_ssl or starttls):          # INFRA-605: never AUTH in cleartext
            return ("failed: refusing to send the SMTP password in cleartext: set ssl = true or starttls = true in [mail]")
    except (ValueError, TypeError) as e:
        return f"failed: {e}"[:300]
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


class Outbox:
    """A bounded queue and one background worker for the hub's outgoing mail (INFRA-606). `submit` never blocks and never
    raises: it returns "queued", or "failed: ..." when the queue is full. Results are counted in `stats`."""

    def __init__(self, sender=None, maxsize: int = QUEUE_MAX):
        self.q: queue.Queue = queue.Queue(maxsize=maxsize)
        self.stats = {"queued": 0, "sent": 0, "failed": 0, "not_configured": 0, "rejected_full": 0}
        self._sender = sender
        self._mu = threading.Lock()
        self._worker: threading.Thread | None = None

    def _count(self, key: str) -> None:
        with self._mu:
            self.stats[key] += 1

    def submit(self, to: str, subject: str, body: str, on_done=None) -> str:
        with self._mu:
            if self._worker is None or not self._worker.is_alive():
                self._worker = threading.Thread(target=self._run, name="havnvard-mail", daemon=True)
                self._worker.start()
        try:
            self.q.put_nowait((to, subject, body, on_done))
        except queue.Full:
            self._count("rejected_full")
            log.error("mail queue full (%s waiting); message to %s NOT queued", self.q.maxsize, to)
            return f"failed: mail queue full ({self.q.maxsize} messages waiting); not sent"
        self._count("queued")
        return "queued"

    def _run(self) -> None:
        while True:
            to, subject, body, on_done = self.q.get()
            try:
                status = (self._sender or send)(to, subject, body)
            except Exception as e:  # noqa: BLE001 - the worker must survive anything; the failure is counted, logged, reported
                status = f"failed: {type(e).__name__}: {e}"[:300]
                log.exception("mail worker error sending to %s", to)
            self._count("sent" if status == "sent" else "not_configured" if status == "not configured" else "failed")
            if status != "sent":
                log.warning("mail to %s: %s", to, status)
            if on_done:
                try:
                    on_done(status)
                except Exception:  # noqa: BLE001 - reporting the result must not kill the worker; logged with traceback
                    log.exception("mail result callback failed for %s", to)
            self.q.task_done()

    def drain(self, timeout: float = 5.0) -> bool:
        """Wait until the queue is empty and handled (tests, orderly shutdown)."""
        import time
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if self.q.unfinished_tasks == 0:
                return True
            time.sleep(0.01)
        return False


OUTBOX = Outbox()
