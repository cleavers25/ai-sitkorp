import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.assessment import engine as assessment_engine
from app.assessment.types import issue, passed
from app.core.enums import FindingCategory as C
from app.core.enums import Role, RunState, ScheduleFrequency
from app.core.enums import Severity as S
from app.models.assessment import Assessment
from app.models.schedule import Schedule, ScheduleRun
from app.services import scheduling
from app.worker.tasks import schedules_tick
from tests.test_ai_chat import add_provider, llm  # noqa: F401  (fixture re-export)

UTC = timezone.utc
RESULTS: dict[str, list] = {}


@pytest.fixture(autouse=True)
def scripted_collect(monkeypatch):
    RESULTS.clear()
    monkeypatch.setattr(assessment_engine._Collector, "collect",
                        lambda self, asset: RESULTS.get(asset.name, [passed("http_availability", C.WEB, "ok")]))


def sched(**kw) -> Schedule:
    base = dict(name="x", frequency=ScheduleFrequency.DAILY, time_of_day="02:00", weekdays=[], minute=0,
                timezone="Asia/Jakarta")
    return Schedule(**{**base, **kw})


# --- next-run computation (WIB = UTC+7) --------------------------------------------

def test_daily_next_run_in_jakarta_time():
    s = sched()
    # 01:00 WIB → 02:00 WIB the same day
    assert scheduling.compute_next_run(s, datetime(2026, 9, 25, 18, 0, tzinfo=UTC)) == datetime(2026, 9, 25, 19, 0, tzinfo=UTC)
    # 03:00 WIB → 02:00 WIB the next day
    assert scheduling.compute_next_run(s, datetime(2026, 9, 25, 20, 0, tzinfo=UTC)) == datetime(2026, 9, 26, 19, 0, tzinfo=UTC)
    # exactly at the firing time → the next day (strictly after)
    assert scheduling.compute_next_run(s, datetime(2026, 9, 25, 19, 0, tzinfo=UTC)) == datetime(2026, 9, 26, 19, 0, tzinfo=UTC)


def test_weekly_and_hourly_next_run():
    weekly = sched(frequency=ScheduleFrequency.WEEKLY, weekdays=[0, 3], time_of_day="07:30")  # Mon & Thu
    # Friday 2026-09-25 10:00 WIB → Monday 2026-09-28 07:30 WIB
    nxt = scheduling.compute_next_run(weekly, datetime(2026, 9, 25, 3, 0, tzinfo=UTC))
    assert nxt == datetime(2026, 9, 28, 0, 30, tzinfo=UTC)
    hourly = sched(frequency=ScheduleFrequency.HOURLY, minute=15)
    assert scheduling.compute_next_run(hourly, datetime(2026, 9, 25, 3, 20, tzinfo=UTC)) == datetime(2026, 9, 25, 4, 15, tzinfo=UTC)
    assert scheduling.compute_next_run(hourly, datetime(2026, 9, 25, 3, 5, tzinfo=UTC)) == datetime(2026, 9, 25, 3, 15, tzinfo=UTC)


# --- API ---------------------------------------------------------------------------

def test_schedule_api_validation_and_permissions(client, admin, as_role):
    ok = client.post("/api/v1/schedules", headers=admin, json={"name": "Harian website"})
    assert ok.status_code == 201, ok.text
    body = ok.json()
    assert body["target"] == "ALL_WEBSITES" and body["time_of_day"] == "02:00" and body["timezone"] == "Asia/Jakarta"
    assert body["next_run_at"] and body["ai_report"] is True

    bad = [{"name": "a", "frequency": "WEEKLY"}, {"name": "a", "timezone": "Mars/Base"},
           {"name": "a", "time_of_day": "25:00"}, {"name": "a", "target": "SELECTED"}]
    for b in bad:
        assert client.post("/api/v1/schedules", headers=admin, json=b).status_code == 422, b
    assert client.post("/api/v1/schedules", headers=as_role(Role.VIEWER), json={"name": "v"}).status_code == 403

    off = client.patch(f"/api/v1/schedules/{body['id']}", headers=admin, json={"enabled": False}).json()
    assert off["next_run_at"] is None
    bad_patch = client.patch(f"/api/v1/schedules/{body['id']}", headers=admin, json={"frequency": "WEEKLY"})
    assert bad_patch.status_code == 422


# --- execution ----------------------------------------------------------------------

def _websites(client, headers, *names):
    return [client.post("/api/v1/websites", headers=headers, json={"url": f"https://{n}"}).json() for n in names]


def test_tick_runs_due_schedule_and_writes_ai_report(client, admin, db, llm):  # noqa: F811
    add_provider(client, admin)
    _websites(client, admin, "aman.example", "bocor.example")
    client.post("/api/v1/servers", headers=admin, json={"name": "srv", "hostname": "10.0.0.5"})  # not targeted
    RESULTS["bocor.example"] = [issue("exposed_file", C.CONFIGURATION, "File .env dapat diunduh publik", S.CRITICAL,
                                      target="https://bocor.example/.env",
                                      evidence={"sample": "DB_PASSWORD=super-rahasia"})]
    sid = client.post("/api/v1/schedules", headers=admin, json={"name": "Harian website"}).json()["id"]
    s = db.get(Schedule, uuid.UUID(sid))
    s.next_run_at = datetime.now(UTC) - timedelta(minutes=1)
    db.commit()

    llm.script = [("text", "## Ringkasan\nbocor.example RED karena .env terbuka.")]
    result = schedules_tick()
    assert len(result["fired"]) == 1 and len(result["report"]) == 1

    db.expire_all()
    run = db.get(ScheduleRun, uuid.UUID(result["fired"][0]))
    assert run.state == RunState.COMPLETED and run.queued == 2 and run.skipped == 0
    assert run.summary["status"] == {"GREEN": 1, "RED": 1} and run.summary["new_findings"] == 1
    assert run.ai_state == "DONE" and "bocor.example" in run.ai_report
    triggers = {a.trigger for a in db.query(Assessment).all()}
    assert triggers == {"SCHEDULED"}
    assert scheduling.as_aware(db.get(Schedule, s.id).next_run_at) > datetime.now(UTC)  # advanced to tomorrow

    prompt = json.dumps(llm.requests[-1])
    assert "bocor.example" in prompt and "File .env" in prompt
    assert "super-rahasia" not in prompt  # evidence never reaches the report prompt
    assert "tools" not in llm.requests[-1]  # one plain call, no tool loop

    # Not due again right away.
    assert schedules_tick()["fired"] == []

    runs = client.get("/api/v1/schedule-runs?with_report=true", headers=admin).json()
    assert runs["total"] == 1 and runs["items"][0]["ai_report"].startswith("## Ringkasan")


def test_run_now_detects_worse_status_and_disabled_schedules_do_not_fire(client, admin, db, llm):  # noqa: F811
    add_provider(client, admin)
    _websites(client, admin, "situs.example")
    sid = client.post("/api/v1/schedules", headers=admin, json={"name": "Manual", "ai_report": False}).json()["id"]

    first = client.post(f"/api/v1/schedules/{sid}/run-now", headers=admin)
    assert first.status_code == 202
    schedules_tick()  # closes the run (eager mode already finished the assessments)

    RESULTS["situs.example"] = [issue("ssl_certificate", C.SSL, "SSL kedaluwarsa", S.HIGH, target="https://situs.example")]
    client.post(f"/api/v1/schedules/{sid}/run-now", headers=admin)
    schedules_tick()
    runs = client.get(f"/api/v1/schedule-runs?schedule_id={sid}", headers=admin).json()["items"]
    latest = runs[0]
    assert latest["summary"]["worse"] == [{"asset": "situs.example", "from": "GREEN", "to": "RED"}]
    assert latest["ai_state"] == "SKIPPED" and latest["trigger"] == "MANUAL"

    client.patch(f"/api/v1/schedules/{sid}", headers=admin, json={"enabled": False})
    s = db.get(Schedule, uuid.UUID(sid))
    s.next_run_at = datetime.now(UTC) - timedelta(minutes=5)
    db.commit()
    assert schedules_tick()["fired"] == []


def test_ai_report_without_provider_is_marked_failed(client, admin, db):
    _websites(client, admin, "a.example")
    sid = client.post("/api/v1/schedules", headers=admin, json={"name": "Tanpa AI provider"}).json()["id"]
    client.post(f"/api/v1/schedules/{sid}/run-now", headers=admin)
    schedules_tick()
    run = client.get(f"/api/v1/schedule-runs?schedule_id={sid}", headers=admin).json()["items"][0]
    assert run["state"] == "COMPLETED" and run["ai_state"] == "FAILED" and "provider" in run["ai_error"].lower()
