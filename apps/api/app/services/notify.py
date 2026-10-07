"""Notifications (PRD 43): events → in-app feed + deliveries to Email/SMTP, Webhook, Telegram.

Events fire on *changes* (new/reopened findings, a status that turned RED, a failed backup),
never on every assessment, so channels are not flooded.
"""

import hashlib
import hmac
import json
import smtplib
import ssl
import uuid
from email.message import EmailMessage
from typing import Any

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.enums import ChannelKind, DeliveryState, Severity
from app.db.base import utcnow
from app.models.notification import NotificationChannel, NotificationDelivery, NotificationEvent
from app.services.secrets import SecretNotFound, get_secret_backend

EVENT_TYPES: dict[str, str] = {
    "asset_red": "Asset berubah menjadi RED",
    "new_findings": "Temuan HIGH/CRITICAL baru",
    "malware": "Dugaan malware baru",
    "ssl": "Masalah sertifikat SSL",
    "unreachable": "Server/website tidak terjangkau",
    "backup_failed": "Backup gagal / tidak terverifikasi",
    "assessment_failed": "Assessment gagal dijalankan",
    "action_pending": "Tindakan menunggu approval",
    "daily_report": "Laporan AI dari jadwal",
    "wazuh_alert": "Alert Wazuh level tinggi",
}
MAX_ATTEMPTS = 3
RETRY_DELAYS = (60, 300)
TIMEOUT = 15


class DeliveryError(Exception):
    pass


def emit(db: Session, type_: str, severity: Severity, title: str, body: str = "", *,
         asset_id: uuid.UUID | None = None, link: str | None = None, data: dict | None = None) -> NotificationEvent:
    """Record an event and queue a delivery for every enabled channel subscribed to its type."""
    from app.worker.tasks import deliver_notification_task

    event = NotificationEvent(id=uuid.uuid4(), type=type_, severity=severity, title=title[:255], body=body[:20000],
                              asset_id=asset_id, link=link, data=data or {})
    db.add(event)
    db.flush()  # no relationship() links the two, so make sure the event row exists before its deliveries
    deliveries = []
    for ch in db.scalars(select(NotificationChannel).where(NotificationChannel.enabled)):
        if type_ in (ch.events or []):
            d = NotificationDelivery(id=uuid.uuid4(), event_id=event.id, channel_id=ch.id)
            db.add(d)
            deliveries.append(d.id)
    db.commit()
    for d_id in deliveries:
        deliver_notification_task.delay(str(d_id))
    return event


# --- rendering ---------------------------------------------------------------------------

def _link(event: NotificationEvent) -> str | None:
    base = get_settings().app_base_url
    return f"{base.rstrip('/')}{event.link}" if base and event.link else None


def render_text(event: NotificationEvent) -> str:
    parts = [f"[{event.severity.value}] {event.title}"]
    if event.body:
        parts.append(event.body)
    if link := _link(event):
        parts.append(f"Buka: {link}")
    parts.append(f"— AI Infra Assistant · {event.created_at:%Y-%m-%d %H:%M} UTC")
    return "\n\n".join(parts)


def webhook_payload(event: NotificationEvent, fmt: str) -> dict[str, Any]:
    if fmt == "slack":  # Slack, Mattermost, Rocket.Chat and Google Chat accept {"text": ...}
        return {"text": render_text(event)}
    return {
        "id": str(event.id), "type": event.type, "type_label": EVENT_TYPES.get(event.type, event.type),
        "severity": event.severity.value, "title": event.title, "body": event.body,
        "asset_id": str(event.asset_id) if event.asset_id else None, "url": _link(event),
        "data": event.data, "created_at": event.created_at.isoformat(),
    }


# --- transports --------------------------------------------------------------------------

def _secret(db: Session, ch: NotificationChannel) -> dict:
    if not ch.secret_path:
        return {}
    try:
        return get_secret_backend(db).get(ch.secret_path)
    except SecretNotFound:
        return {}


def send_email(cfg: dict, secret: dict, subject: str, text: str) -> None:
    host, port = cfg.get("host"), int(cfg.get("port") or 587)
    if not host or not cfg.get("from_address") or not cfg.get("to"):
        raise DeliveryError("Konfigurasi SMTP belum lengkap (host, pengirim, penerima).")
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = cfg["from_address"]
    msg["To"] = ", ".join(cfg["to"])
    msg.set_content(text)
    security = cfg.get("security", "starttls")
    context = ssl.create_default_context()
    if not cfg.get("verify_tls", True):
        context.check_hostname, context.verify_mode = False, ssl.CERT_NONE
    try:
        if security == "ssl":
            server = smtplib.SMTP_SSL(host, port, timeout=TIMEOUT, context=context)
        else:
            server = smtplib.SMTP(host, port, timeout=TIMEOUT)
        with server:
            if security == "starttls":
                server.starttls(context=context)
            if cfg.get("username"):
                server.login(cfg["username"], secret.get("password", ""))
            server.send_message(msg)
    except (smtplib.SMTPException, OSError, ssl.SSLError) as exc:
        raise DeliveryError(f"SMTP: {type(exc).__name__}: {exc}"[:500])


def send_webhook(cfg: dict, secret: dict, event: NotificationEvent, transport=None) -> None:
    url = cfg.get("url")
    if not url:
        raise DeliveryError("URL webhook belum diisi.")
    body = json.dumps(webhook_payload(event, cfg.get("format", "json")), ensure_ascii=False).encode()
    headers = {"Content-Type": "application/json", "User-Agent": "AIInfraAssistant-Webhook/1.0",
               "X-AIInfra-Event": event.type, "X-AIInfra-Delivery": str(event.id)}
    if key := secret.get("signing_secret"):
        headers["X-AIInfra-Signature"] = "sha256=" + hmac.new(key.encode(), body, hashlib.sha256).hexdigest()
    try:
        with httpx.Client(timeout=TIMEOUT, transport=transport, verify=cfg.get("verify_tls", True)) as c:
            r = c.post(url, content=body, headers=headers)
    except httpx.HTTPError as exc:
        raise DeliveryError(f"Webhook: {type(exc).__name__}: {exc}"[:500])
    if r.status_code >= 300:
        raise DeliveryError(f"Webhook membalas HTTP {r.status_code}: {r.text[:200]}")


def send_telegram(cfg: dict, secret: dict, text: str, transport=None) -> None:
    token, chat = secret.get("bot_token"), cfg.get("chat_id")
    if not token or not chat:
        raise DeliveryError("Bot token / chat id Telegram belum diisi.")
    try:
        with httpx.Client(timeout=TIMEOUT, transport=transport) as c:
            r = c.post(f"https://api.telegram.org/bot{token}/sendMessage",
                       json={"chat_id": chat, "text": text[:4000], "disable_web_page_preview": True})
    except httpx.HTTPError as exc:
        raise DeliveryError(f"Telegram: {type(exc).__name__}")  # never echo the URL: it contains the token
    if r.status_code != 200:
        raise DeliveryError(f"Telegram membalas HTTP {r.status_code}: {r.json().get('description', '')[:200]}")


HTTP_TRANSPORT = None  # test hook


def dispatch(db: Session, ch: NotificationChannel, event: NotificationEvent) -> None:
    secret = _secret(db, ch)
    text = render_text(event)
    if ch.kind == ChannelKind.EMAIL:
        send_email(ch.config, secret, f"[AI Infra][{event.severity.value}] {event.title}", text)
    elif ch.kind == ChannelKind.WEBHOOK:
        send_webhook(ch.config, secret, event, HTTP_TRANSPORT)
    else:
        send_telegram(ch.config, secret, text, HTTP_TRANSPORT)


def deliver(db: Session, delivery_id: uuid.UUID) -> dict:
    """Try once; returns {'retry_in': seconds} when the caller should retry later."""
    d = db.get(NotificationDelivery, delivery_id)
    if d is None or d.state != DeliveryState.PENDING:
        return {"state": "SKIPPED"}
    ch, event = db.get(NotificationChannel, d.channel_id), db.get(NotificationEvent, d.event_id)
    d.attempts += 1
    try:
        dispatch(db, ch, event)
        d.state, d.sent_at, d.last_error = DeliveryState.SENT, utcnow(), None
    except DeliveryError as exc:
        d.last_error = str(exc)
        if d.attempts >= MAX_ATTEMPTS:
            d.state = DeliveryState.FAILED
    db.commit()
    if d.state == DeliveryState.PENDING:
        return {"state": "PENDING", "retry_in": RETRY_DELAYS[min(d.attempts - 1, len(RETRY_DELAYS) - 1)]}
    return {"state": d.state.value}


def test_channel(db: Session, ch: NotificationChannel) -> tuple[bool, str]:
    event = NotificationEvent(id=uuid.uuid4(), type="test", severity=Severity.INFO,
                              title="Tes notifikasi AI Infra Assistant",
                              body=f"Kanal '{ch.name}' berhasil dikonfigurasi.", created_at=utcnow(), data={})
    try:
        dispatch(db, ch, event)
        return True, "Terkirim."
    except DeliveryError as exc:
        return False, str(exc)
