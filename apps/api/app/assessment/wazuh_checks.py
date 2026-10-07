"""Server checks sourced from Wazuh (no SSH): agent health, high-level alerts, FIM, CVEs, SCA score."""

import re

from sqlalchemy.orm import Session

from app.assessment.types import CheckResult, clip, error, issue, passed, skipped
from app.core.enums import FindingCategory as C
from app.core.enums import Severity as S
from app.models.asset import Server
from app.services import wazuh

LOOKBACK_HOURS = 24
WEB_PATHS = re.compile(r"^(/var/www/|/srv/|/home/[^/]+/(public_html|www)/|/usr/share/nginx/)")
SCRIPT_EXT = re.compile(r"\.(php\d?|phtml|phar|sh|py|pl|cgi|js)$", re.I)


def level_severity(level: int) -> S:
    if level >= 13:
        return S.CRITICAL
    if level >= 10:
        return S.HIGH
    if level >= 7:
        return S.MEDIUM
    return S.LOW


def eval_alerts(resp: dict, min_level: int) -> list[CheckResult]:
    buckets = resp.get("aggregations", {}).get("rules", {}).get("buckets", [])
    results = []
    for b in buckets:
        level = int(b.get("max_level", {}).get("value") or 0)
        if level < min_level:
            continue
        hit = (b.get("latest", {}).get("hits", {}).get("hits") or [{}])[0].get("_source", {})
        rule = hit.get("rule", {})
        desc = rule.get("description") or f"rule {b['key']}"
        results.append(issue(
            "wazuh_alerts", C.SECURITY_EVENT, f"Wazuh: {desc} ({b['doc_count']}× / {LOOKBACK_HOURS} jam)"[:255],
            level_severity(level), target=f"rule:{b['key']}", value=f"level {level}",
            evidence={"rule_id": b["key"], "level": level, "count": b["doc_count"], "groups": rule.get("groups"),
                      "last_seen": hit.get("timestamp"), "srcip": hit.get("data", {}).get("srcip"),
                      "sample": clip(hit.get("full_log"), 600)},
            confidence=0.8,
            description="Alert dari Wazuh. Tinjau konteks event (sumber, user, proses) sebelum menyimpulkan kompromi.",
            recommendation="Buka event di Wazuh Dashboard, korelasikan dengan temuan lain di asset ini, lalu tentukan "
                           "apakah perlu insiden/containment."))
    if not results:
        total = resp.get("hits", {}).get("total", {})
        total = total.get("value", 0) if isinstance(total, dict) else total
        results.append(passed("wazuh_alerts", C.SECURITY_EVENT,
                              f"Tidak ada alert Wazuh level ≥ {min_level} dalam {LOOKBACK_HOURS} jam", value=str(total)))
    return results


def eval_fim(events: list[dict]) -> list[CheckResult]:
    counts: dict[str, int] = {}
    suspicious = []
    for e in events:
        sc = e.get("syscheck", {})
        ev, path = sc.get("event", "?"), sc.get("path") or ""
        counts[ev] = counts.get(ev, 0) + 1
        if ev in ("added", "modified") and WEB_PATHS.match(path) and SCRIPT_EXT.search(path):
            suspicious.append({"path": path, "event": ev, "time": e.get("timestamp"),
                               "sha256": sc.get("sha256_after"), "user": (sc.get("uname_after") or "")})
    ev = {"events_24h": counts, "suspicious": suspicious[:30]}
    if suspicious:
        return [issue("wazuh_fim", C.FIM, f"{len(suspicious)} file skrip di folder web berubah/baru (FIM Wazuh)",
                      S.MEDIUM, value=", ".join(sorted({s['path'] for s in suspicious}))[:255], evidence=ev,
                      confidence=0.6,
                      description="Perubahan file skrip di folder web bisa normal (deploy) atau tanda webshell.",
                      recommendation="Cocokkan dengan jadwal deploy. Jika tidak ada deploy, periksa isi file dan "
                                     "jalankan assessment website untuk scan malware.")]
    return [passed("wazuh_fim", C.FIM, f"FIM: {sum(counts.values())} event, tidak ada skrip web mencurigakan",
                   evidence=ev)]


def eval_vulns(resp: dict) -> list[CheckResult]:
    by_sev = {b["key"]: b["doc_count"] for b in resp.get("aggregations", {}).get("by_severity", {}).get("buckets", [])}
    top = []
    for h in resp.get("hits", {}).get("hits", []):
        src = h.get("_source", {})
        v, pkg = src.get("vulnerability", {}), src.get("package", {})
        top.append({"cve": v.get("id"), "severity": v.get("severity"), "score": (v.get("score") or {}).get("base"),
                    "package": pkg.get("name"), "version": pkg.get("version")})
    results = []
    rec = "Update paket yang terdampak (prioritaskan yang terekspos ke internet), lalu verifikasi ulang di Wazuh."
    for sev_name, finding_sev in (("Critical", S.HIGH), ("High", S.MEDIUM)):
        n = by_sev.get(sev_name, 0)
        if n:
            results.append(issue(
                "wazuh_vulnerabilities", C.VULNERABILITY, f"{n} kerentanan {sev_name} (Wazuh)", finding_sev,
                target=f"severity:{sev_name}", value=str(n),
                evidence={"counts": by_sev, "top": [t for t in top if t["severity"] == sev_name][:20]},
                recommendation=rec))
    if not results:
        results.append(passed("wazuh_vulnerabilities", C.VULNERABILITY,
                              "Tidak ada kerentanan Critical/High (Wazuh)", evidence={"counts": by_sev}))
    return results


def eval_sca(policies: list[dict]) -> list[CheckResult]:
    if not policies:
        return [skipped("wazuh_sca", C.CONFIGURATION, "Belum ada hasil SCA dari Wazuh")]
    worst = min(policies, key=lambda p: p.get("score", 100))
    score = worst.get("score", 100)
    ev = {"policies": [{k: p.get(k) for k in ("policy_id", "name", "score", "pass", "fail", "end_scan")} for p in policies]}
    rec = "Tinjau check SCA yang gagal di Wazuh Dashboard dan perbaiki hardening yang relevan."
    if score < 50:
        return [issue("wazuh_sca", C.CONFIGURATION, f"Skor hardening (SCA) rendah: {score}%", S.MEDIUM,
                      target=worst.get("policy_id"), value=f"{score}%", evidence=ev, recommendation=rec)]
    if score < 70:
        return [issue("wazuh_sca", C.CONFIGURATION, f"Skor hardening (SCA) {score}%", S.LOW,
                      target=worst.get("policy_id"), value=f"{score}%", evidence=ev, recommendation=rec)]
    return [passed("wazuh_sca", C.CONFIGURATION, f"Skor hardening (SCA) {score}%", value=f"{score}%", evidence=ev)]


def run_wazuh_checks(db: Session, server: Server) -> list[CheckResult]:
    if not wazuh.is_enabled(db):
        return []
    agent = wazuh.agent_for_server(db, server.id)
    if agent is None:
        return [skipped("wazuh_agent", C.SECURITY_EVENT, "Server belum terhubung ke agent Wazuh",
                        recommendation="Pasang agent Wazuh atau petakan agent di menu Integrasi Wazuh.")]
    try:
        client = wazuh.WazuhClient.from_db(db)
        results = []
        live = next((a for a in client.agents() if str(a.get("id")) == agent.agent_id), None)
        status = (live or {}).get("status", agent.status)
        if status == "active":
            results.append(passed("wazuh_agent", C.SECURITY_EVENT, f"Agent Wazuh {agent.agent_id} aktif",
                                  value=agent.name, evidence={"version": (live or {}).get("version")}))
        else:
            results.append(issue("wazuh_agent", C.SECURITY_EVENT, f"Agent Wazuh {agent.agent_id} {status}",
                                 S.MEDIUM, value=status, evidence={"last_keepalive": (live or {}).get("lastKeepAlive")},
                                 recommendation="Periksa service wazuh-agent dan konektivitas ke Wazuh manager."))
        cfg = client.cfg
        results += eval_alerts(client.alerts(agent.agent_id, LOOKBACK_HOURS, cfg.min_alert_level), cfg.min_alert_level)
        results += eval_fim(client.fim_events(agent.agent_id, LOOKBACK_HOURS))
        results += eval_vulns(client.vulnerabilities(agent.agent_id, ["Critical", "High"]))
        results += eval_sca(client.sca(agent.agent_id))
        return results
    except wazuh.WazuhError as exc:
        return [error("wazuh", C.SECURITY_EVENT, str(exc))]
