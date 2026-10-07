"""Read-only Wazuh integration (PRD 34, Phase 5): Server API (agents, SCA) + Indexer (alerts, FIM, CVEs).

Endpoints/indices follow the Wazuh 4.x documentation:
  POST /security/user/authenticate?raw=true   (basic auth → JWT, sent as Bearer)
  GET  /agents, GET /sca/{agent_id}           (data.affected_items)
  POST <indexer>/wazuh-alerts-*/_search
  POST <indexer>/wazuh-states-vulnerabilities-*/_search
Queries are OpenSearch JSON DSL built from structured values, never string concatenation.
"""

import ssl
from dataclasses import dataclass
from typing import Any

import httpx
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.base import utcnow
from app.models.asset import Server
from app.models.wazuh import WazuhAgent, WazuhConfig
from app.services.secrets import SecretNotFound, get_secret_backend

ALERTS = "wazuh-alerts-*"
VULNS = "wazuh-states-vulnerabilities-*"
TIMEOUT = 20
HTTP_TRANSPORT = None  # test hook


class WazuhError(Exception):
    pass


def get_config(db: Session) -> WazuhConfig:
    cfg = db.scalars(select(WazuhConfig).limit(1)).first()
    if cfg is None:
        cfg = WazuhConfig()
        db.add(cfg)
        db.commit()
    return cfg


def is_enabled(db: Session) -> bool:
    cfg = db.scalars(select(WazuhConfig).limit(1)).first()
    return bool(cfg and cfg.enabled and cfg.api_url)


@dataclass
class WazuhClient:
    cfg: WazuhConfig
    api_password: str | None
    indexer_password: str | None
    _token: str | None = None

    @classmethod
    def from_db(cls, db: Session) -> "WazuhClient":
        cfg = get_config(db)
        if not cfg.api_url:
            raise WazuhError("Integrasi Wazuh belum dikonfigurasi.")
        secret = {}
        if cfg.secret_path:
            try:
                secret = get_secret_backend(db).get(cfg.secret_path)
            except SecretNotFound:
                pass
        return cls(cfg, secret.get("api_password"), secret.get("indexer_password"))

    def _verify(self):
        if not self.cfg.verify_tls:
            return False
        if self.cfg.ca_cert:
            return ssl.create_default_context(cadata=self.cfg.ca_cert)
        return True

    def _client(self) -> httpx.Client:
        return httpx.Client(timeout=TIMEOUT, verify=self._verify(), transport=HTTP_TRANSPORT)

    # --- Server API ------------------------------------------------------------------
    def _auth(self, c: httpx.Client) -> str:
        try:
            r = c.post(f"{self.cfg.api_url.rstrip('/')}/security/user/authenticate", params={"raw": "true"},
                       auth=(self.cfg.api_user or "", self.api_password or ""))
        except httpx.HTTPError as exc:
            raise WazuhError(f"Tidak bisa terhubung ke Wazuh API: {type(exc).__name__}: {exc}"[:300])
        if r.status_code != 200:
            raise WazuhError(f"Login Wazuh API gagal (HTTP {r.status_code}). Periksa user/password API.")
        return r.text.strip().strip('"')

    def api_get(self, path: str, params: dict | None = None) -> dict:
        with self._client() as c:
            for attempt in (1, 2):
                if not self._token:
                    self._token = self._auth(c)
                try:
                    r = c.get(f"{self.cfg.api_url.rstrip('/')}{path}", params=params,
                              headers={"Authorization": f"Bearer {self._token}"})
                except httpx.HTTPError as exc:
                    raise WazuhError(f"Wazuh API: {type(exc).__name__}: {exc}"[:300])
                if r.status_code == 401 and attempt == 1:
                    self._token = None  # token expired: log in again once
                    continue
                if r.status_code != 200:
                    raise WazuhError(f"Wazuh API {path} membalas HTTP {r.status_code}: {r.text[:200]}")
                return r.json()
        raise WazuhError("Wazuh API: autentikasi gagal")

    def agents(self) -> list[dict]:
        items, offset = [], 0
        while True:
            data = self.api_get("/agents", {
                "limit": 500, "offset": offset,
                "select": "id,name,ip,status,os.name,os.version,version,lastKeepAlive,group"})["data"]
            batch = data.get("affected_items", [])
            items += batch
            offset += len(batch)
            if not batch or offset >= data.get("total_affected_items", 0):
                return items

    def sca(self, agent_id: str) -> list[dict]:
        return self.api_get(f"/sca/{agent_id}")["data"].get("affected_items", [])

    # --- Indexer ---------------------------------------------------------------------
    def search(self, index: str, body: dict) -> dict:
        if not self.cfg.indexer_url:
            raise WazuhError("URL Wazuh Indexer belum diisi.")
        try:
            with self._client() as c:
                r = c.post(f"{self.cfg.indexer_url.rstrip('/')}/{index}/_search", json=body,
                           auth=(self.cfg.indexer_user or "", self.indexer_password or ""))
        except httpx.HTTPError as exc:
            raise WazuhError(f"Tidak bisa terhubung ke Wazuh Indexer: {type(exc).__name__}: {exc}"[:300])
        if r.status_code != 200:
            raise WazuhError(f"Wazuh Indexer membalas HTTP {r.status_code}: {r.text[:200]}")
        return r.json()

    def indexer_info(self) -> dict:
        with self._client() as c:
            r = c.get(self.cfg.indexer_url.rstrip("/"), auth=(self.cfg.indexer_user or "", self.indexer_password or ""))
        if r.status_code != 200:
            raise WazuhError(f"Login Wazuh Indexer gagal (HTTP {r.status_code}).")
        return r.json()

    def alerts(self, agent_id: str | None, hours: int, min_level: int, size: int = 20,
               extra_filter: list | None = None) -> dict:
        filters: list[dict] = [{"range": {"timestamp": {"gte": f"now-{int(hours)}h"}}},
                               {"range": {"rule.level": {"gte": int(min_level)}}}]
        if agent_id:
            filters.append({"term": {"agent.id": agent_id}})
        filters += extra_filter or []
        body = {
            "size": size, "track_total_hits": True, "sort": [{"timestamp": {"order": "desc"}}],
            "query": {"bool": {"filter": filters}},
            "aggs": {"rules": {"terms": {"field": "rule.id", "size": 25},
                               "aggs": {"max_level": {"max": {"field": "rule.level"}},
                                        "latest": {"top_hits": {"size": 1, "sort": [{"timestamp": {"order": "desc"}}]}}}}},
        }
        return self.search(ALERTS, body)

    def fim_events(self, agent_id: str, hours: int, size: int = 200) -> list[dict]:
        body = {"size": size, "sort": [{"timestamp": {"order": "desc"}}], "query": {"bool": {"filter": [
            {"term": {"agent.id": agent_id}}, {"term": {"rule.groups": "syscheck"}},
            {"range": {"timestamp": {"gte": f"now-{int(hours)}h"}}}]}}}
        return [h["_source"] for h in self.search(ALERTS, body).get("hits", {}).get("hits", [])]

    def vulnerabilities(self, agent_id: str, severities: list[str] | None = None, size: int = 50) -> dict:
        filters: list[dict] = [{"term": {"agent.id": agent_id}}]
        if severities:
            filters.append({"terms": {"vulnerability.severity": severities}})
        body = {"size": size, "track_total_hits": True, "sort": [{"vulnerability.score.base": {"order": "desc"}}],
                "query": {"bool": {"filter": filters}},
                "aggs": {"by_severity": {"terms": {"field": "vulnerability.severity", "size": 10}}}}
        return self.search(VULNS, body)

    def search_ioc(self, value: str, hours: int, size: int = 50) -> dict:
        """Look an indicator (IP, hash, file name, domain) up across all agents' alerts."""
        fields = ["data.srcip", "data.dstip", "agent.ip", "syscheck.path", "syscheck.sha256_after",
                  "syscheck.md5_after", "syscheck.sha1_after", "data.url", "data.hostname", "full_log"]
        body = {
            "size": size, "track_total_hits": True, "sort": [{"timestamp": {"order": "desc"}}],
            "query": {"bool": {"filter": [{"range": {"timestamp": {"gte": f"now-{int(hours)}h"}}}],
                               "must": [{"multi_match": {"query": value, "fields": fields, "type": "phrase",
                                                         "lenient": True}}]}},
            "aggs": {"agents": {"terms": {"field": "agent.name", "size": 50}}},
        }
        return self.search(ALERTS, body)


# --- sync & mapping ------------------------------------------------------------------------

def _auto_match(db: Session, agent: WazuhAgent) -> Server | None:
    keys = {k.lower() for k in (agent.name, agent.ip) if k}
    for s in db.scalars(select(Server)):
        if s.hostname.lower() in keys or s.name.lower() in keys:
            return s
    return None


def sync_agents(db: Session, client: WazuhClient | None = None) -> dict:
    cfg = get_config(db)
    try:
        client = client or WazuhClient.from_db(db)
        items = client.agents()
    except WazuhError as exc:
        cfg.last_sync_at, cfg.last_sync_ok, cfg.last_sync_error = utcnow(), False, str(exc)
        db.commit()
        raise
    existing = {a.agent_id: a for a in db.scalars(select(WazuhAgent))}
    seen = set()
    for it in items:
        aid = str(it.get("id"))
        if aid == "000":
            continue  # the manager itself
        seen.add(aid)
        # mapping set explicitly: column defaults only apply at INSERT, but it is read below before flush.
        a = existing.get(aid) or WazuhAgent(agent_id=aid, name=it.get("name") or aid, mapping="AUTO")
        if aid not in existing:
            db.add(a)
        os_ = it.get("os") or {}
        a.name, a.ip, a.status = it.get("name") or aid, it.get("ip"), it.get("status")
        a.os_name, a.os_version, a.version = os_.get("name"), os_.get("version"), it.get("version")
        a.last_keepalive, a.groups, a.raw = it.get("lastKeepAlive"), it.get("group") or [], it
        if a.mapping == "AUTO":
            match = _auto_match(db, a)
            a.server_id = match.id if match else None
    for aid, a in existing.items():
        if aid not in seen:
            a.status = "removed"
    cfg.last_sync_at, cfg.last_sync_ok, cfg.last_sync_error = utcnow(), True, None
    db.commit()
    mapped = db.scalar(select(func.count()).select_from(WazuhAgent).where(WazuhAgent.server_id.is_not(None)))
    return {"agents": len(seen), "mapped": mapped}


def agent_for_server(db: Session, server_id) -> WazuhAgent | None:
    return db.scalars(select(WazuhAgent).where(WazuhAgent.server_id == server_id)).first()
