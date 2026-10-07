"""Near-real-time notifications for high-level Wazuh alerts (polled every few minutes by the scheduler)."""

from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.assessment.wazuh_checks import level_severity
from app.db.base import utcnow
from app.models.asset import Server
from app.models.wazuh import WazuhAgent
from app.services import wazuh
from app.services.assessments import as_aware
from app.services.notify import emit

FIRST_WINDOW = timedelta(minutes=10)
MAX_EVENTS = 20


def poll(db: Session) -> dict:
    if not wazuh.is_enabled(db):
        return {"skipped": "disabled"}
    cfg = wazuh.get_config(db)
    if not cfg.indexer_url:
        return {"skipped": "no indexer"}
    now = utcnow()
    since = as_aware(cfg.last_alert_poll_at) if cfg.last_alert_poll_at else now - FIRST_WINDOW
    body = {
        "size": 0,
        "query": {"bool": {"filter": [{"range": {"timestamp": {"gt": since.isoformat(), "lte": now.isoformat()}}},
                                      {"range": {"rule.level": {"gte": cfg.min_alert_level}}}]}},
        "aggs": {"pairs": {"multi_terms": {"terms": [{"field": "agent.id"}, {"field": "rule.id"}], "size": MAX_EVENTS},
                           "aggs": {"max_level": {"max": {"field": "rule.level"}},
                                    "latest": {"top_hits": {"size": 1, "sort": [{"timestamp": {"order": "desc"}}]}}}}},
    }
    resp = wazuh.WazuhClient.from_db(db).search(wazuh.ALERTS, body)
    agents = {a.agent_id: a for a in db.scalars(select(WazuhAgent))}
    sent = 0
    for b in resp.get("aggregations", {}).get("pairs", {}).get("buckets", []):
        agent_id, rule_id = (str(k) for k in b["key"])
        level = int(b.get("max_level", {}).get("value") or 0)
        src = (b.get("latest", {}).get("hits", {}).get("hits") or [{}])[0].get("_source", {})
        agent = agents.get(agent_id)
        server = db.get(Server, agent.server_id) if agent and agent.server_id else None
        who = server.name if server else (src.get("agent", {}).get("name") or f"agent {agent_id}")
        desc = src.get("rule", {}).get("description") or f"rule {rule_id}"
        emit(db, "wazuh_alert", level_severity(level), f"Wazuh level {level} di {who}: {desc}"[:255],
             f"{b['doc_count']} alert sejak {since:%H:%M} UTC.\nContoh: {(src.get('full_log') or '')[:500]}",
             asset_id=server.id if server else None,
             link=f"/servers/{server.id}" if server else None,
             data={"agent_id": agent_id, "rule_id": rule_id, "level": level, "count": b["doc_count"]})
        sent += 1
    cfg.last_alert_poll_at = now
    db.commit()
    return {"events": sent}
