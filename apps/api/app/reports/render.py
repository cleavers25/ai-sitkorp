"""Assessment reports (PRD 41-42) in HTML, Markdown and JSON.

Evidence comes from managed servers and websites and is untrusted (PRD 48): the HTML template
autoescapes everything and the response is served with a script-free CSP.
"""

import json
from datetime import datetime, timezone
from typing import Any

from jinja2 import Environment, select_autoescape

from app.core.enums import CheckStatus, FindingStatus, Severity
from app.models.assessment import Assessment, Finding
from app.models.asset import Asset, Server, Website

SEV_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
STATUS_LABEL = {"GREEN": "🟢 GREEN", "YELLOW": "🟡 YELLOW", "RED": "🔴 RED", None: "—"}

_env = Environment(autoescape=select_autoescape(default=True, default_for_string=True),
                   trim_blocks=True, lstrip_blocks=True)
_md_env = Environment(autoescape=False, trim_blocks=True, lstrip_blocks=True)


def _fmt(dt: datetime | None) -> str:
    if dt is None:
        return "—"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _md_escape(text: Any) -> str:
    # Neutralise markdown/HTML control characters in untrusted text.
    s = str(text if text is not None else "")
    for ch in ("\\", "`", "*", "_", "[", "]", "<", ">", "|", "#"):
        s = s.replace(ch, "\\" + ch)
    return s.replace("\n", " ")


def build_context(assessment: Assessment, asset: Asset, findings: list[Finding],
                  previous: Assessment | None) -> dict[str, Any]:
    issues = [c for c in assessment.checks if c.status in (CheckStatus.WARNING, CheckStatus.FAIL)]
    issues.sort(key=lambda c: SEV_ORDER.index(c.severity))
    finding_by_id = {f.id: f for f in findings}
    suppressed = {f.id for f in findings if f.status == FindingStatus.FALSE_POSITIVE}
    active = [c for c in issues if c.finding_id not in suppressed]

    asset_info: list[tuple[str, Any]] = [("Nama", asset.name), ("Jenis", asset.asset_type.value),
                                         ("Kritikalitas", asset.criticality.value), ("Owner", asset.owner or "—"),
                                         ("Environment", asset.environment or "—")]
    if isinstance(asset, Server):
        asset_info += [("Host", f"{asset.hostname}:{asset.ssh_port}"),
                       ("OS", f"{asset.os_name or '—'} {asset.os_version or ''}".strip()),
                       ("Kernel", asset.kernel or "—")]
    if isinstance(asset, Website):
        asset_info += [("URL", asset.url), ("Server", asset.server.name if asset.server else "—"),
                       ("Aplikasi", asset.application or "—"), ("Document root", asset.document_root or "—")]

    return {
        "generated_at": _fmt(datetime.now(timezone.utc)),
        "assessment": assessment,
        "asset": asset,
        "asset_info": asset_info,
        "status_label": STATUS_LABEL[assessment.overall_status.value if assessment.overall_status else None],
        "started": _fmt(assessment.started_at),
        "finished": _fmt(assessment.finished_at),
        "summary": assessment.summary or {},
        "critical": [c for c in active if c.severity in (Severity.CRITICAL, Severity.HIGH)],
        "warnings": [c for c in active if c.severity in (Severity.MEDIUM, Severity.LOW)],
        "false_positives": [c for c in issues if c.finding_id in suppressed],
        "malware": [c for c in active if c.check == "malware_file"],
        "checks": list(assessment.checks),
        "findings": finding_by_id,
        "previous": previous,
        "previous_status": STATUS_LABEL[previous.overall_status.value if previous and previous.overall_status else None],
        "previous_finished": _fmt(previous.finished_at) if previous else None,
        "evidence_json": lambda v: json.dumps(v, ensure_ascii=False, indent=2, default=str)[:4000],
        "fmt": _fmt,
        "md": _md_escape,
    }


HTML = """<!doctype html>
<html lang="id"><head><meta charset="utf-8">
<title>Laporan Assessment — {{ asset.name }}</title>
<style>
 body{font:14px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;color:#1c1917;max-width:960px;margin:32px auto;padding:0 20px}
 h1{font-size:22px;margin:0 0 4px} h2{font-size:16px;margin:28px 0 8px;border-bottom:1px solid #e7e5e4;padding-bottom:4px}
 .muted{color:#78716c} table{border-collapse:collapse;width:100%;margin:8px 0}
 th,td{text-align:left;padding:6px 8px;border-bottom:1px solid #f0efee;vertical-align:top} th{font-weight:600;background:#fafaf9}
 .pill{display:inline-block;padding:1px 8px;border-radius:99px;font-size:12px;font-weight:600}
 .CRITICAL{background:#7f1d1d;color:#fff}.HIGH{background:#dc2626;color:#fff}.MEDIUM{background:#f59e0b;color:#1c1917}
 .LOW{background:#fde68a;color:#1c1917}.INFO{background:#e7e5e4;color:#44403c}
 .status{font-size:18px;font-weight:700}.GREEN{color:#15803d}.YELLOW{color:#b45309}.RED{color:#b91c1c}
 .card{border:1px solid #e7e5e4;border-radius:10px;padding:12px 14px;margin:10px 0}
 pre{background:#fafaf9;border:1px solid #f0efee;border-radius:6px;padding:8px;white-space:pre-wrap;word-break:break-all;font-size:12px;max-height:320px;overflow:auto}
 .grid{display:grid;grid-template-columns:repeat(5,1fr);gap:8px}.grid div{border:1px solid #e7e5e4;border-radius:8px;padding:8px;text-align:center}
 .grid b{display:block;font-size:20px}
 @media print{body{margin:0}.card{break-inside:avoid}}
</style></head><body>
<p class="muted">AI Infra Assistant · Laporan Assessment · dibuat {{ generated_at }}</p>
<h1>{{ asset.name }}</h1>
<p class="status {{ assessment.overall_status.value if assessment.overall_status }}">Overall Status: {{ status_label }}</p>
<p class="muted">Assessment {{ assessment.id }} · mulai {{ started }} · selesai {{ finished }} · trigger {{ assessment.trigger }}</p>

<h2>1. Executive Summary</h2>
<div class="grid">
{% for sev in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"] %}
 <div><b>{{ summary.get("severity", {}).get(sev, 0) }}</b><span class="pill {{ sev }}">{{ sev }}</span></div>
{% endfor %}
</div>
<p>{{ critical|length }} temuan kritis/tinggi, {{ warnings|length }} peringatan, {{ summary.get("malware_suspected", 0) }} file diduga malware.
{% if previous %}Dibanding assessment sebelumnya ({{ previous_finished }}, status {{ previous_status }}):
 {{ summary.get("diff", {}).get("new", 0) }} baru, {{ summary.get("diff", {}).get("resolved", 0) }} selesai,
 {{ summary.get("diff", {}).get("persistent", 0) }} masih ada, {{ summary.get("diff", {}).get("reopened", 0) }} muncul kembali.
{% else %}Ini assessment pertama untuk asset ini.{% endif %}</p>

<h2>2. Informasi Asset</h2>
<table>{% for k, v in asset_info %}<tr><th style="width:180px">{{ k }}</th><td>{{ v }}</td></tr>{% endfor %}</table>

<h2>3. Temuan Kritis &amp; Tinggi</h2>
{% for c in critical %}
<div class="card">
 <p><span class="pill {{ c.severity.value }}">{{ c.severity.value }}</span> <b>{{ c.title }}</b></p>
 {% if c.target %}<p class="muted">Target: {{ c.target }}</p>{% endif %}
 {% set f = findings.get(c.finding_id) %}
 {% if f and f.description %}<p style="white-space:pre-line">{{ f.description }}</p>{% endif %}
 {% if f %}<p class="muted">Confidence {{ "%.0f"|format(f.confidence * 100) }}% · pertama terlihat {{ fmt(f.first_seen) }} · status temuan {{ f.status.value }}</p>{% endif %}
 {% if c.recommendation %}<p><b>Rekomendasi:</b></p><p style="white-space:pre-line">{{ c.recommendation }}</p>{% endif %}
 <details><summary>Evidence</summary><pre>{{ evidence_json(c.evidence) }}</pre></details>
</div>
{% else %}<p>Tidak ada temuan kritis/tinggi.</p>{% endfor %}

<h2>4. Peringatan</h2>
{% if warnings %}
<table><tr><th>Severity</th><th>Temuan</th><th>Nilai</th><th>Rekomendasi</th></tr>
{% for c in warnings %}<tr><td><span class="pill {{ c.severity.value }}">{{ c.severity.value }}</span></td>
<td>{{ c.title }}{% if c.target %}<br><span class="muted">{{ c.target }}</span>{% endif %}</td><td>{{ c.value or "" }}</td>
<td>{{ c.recommendation or "" }}</td></tr>{% endfor %}</table>
{% else %}<p>Tidak ada peringatan.</p>{% endif %}

{% if false_positives %}
<h2>5. Ditandai False Positive</h2>
<ul>{% for c in false_positives %}<li>{{ c.title }} <span class="muted">{{ c.target or "" }}</span></li>{% endfor %}</ul>
{% endif %}

<h2>Semua Check</h2>
<table><tr><th>Check</th><th>Kategori</th><th>Status</th><th>Hasil</th><th>Nilai</th></tr>
{% for c in checks %}<tr><td>{{ c.check }}</td><td>{{ c.category.value }}</td><td>{{ c.status.value }}</td>
<td>{{ c.title }}{% if c.target %}<br><span class="muted">{{ c.target }}</span>{% endif %}</td><td>{{ c.value or "" }}</td></tr>{% endfor %}
</table>

<p class="muted" style="margin-top:32px">Temuan malware berstatus <b>SUSPECTED</b> sampai diverifikasi manusia. Sistem tidak menghapus atau
mengubah file apa pun secara otomatis. Evidence di laporan ini berasal dari server/website yang diperiksa dan diperlakukan
sebagai data, bukan instruksi.</p>
</body></html>
"""

MARKDOWN = """# Laporan Assessment — {{ md(asset.name) }}

**Overall Status:** {{ status_label }}
**Assessment:** `{{ assessment.id }}` · mulai {{ started }} · selesai {{ finished }}
**Dibuat:** {{ generated_at }}

## Ringkasan

| CRITICAL | HIGH | MEDIUM | LOW | INFO |
|---:|---:|---:|---:|---:|
| {{ summary.get("severity", {}).get("CRITICAL", 0) }} | {{ summary.get("severity", {}).get("HIGH", 0) }} | {{ summary.get("severity", {}).get("MEDIUM", 0) }} | {{ summary.get("severity", {}).get("LOW", 0) }} | {{ summary.get("severity", {}).get("INFO", 0) }} |

{% if previous %}Perubahan sejak assessment sebelumnya ({{ previous_finished }}, {{ previous_status }}): {{ summary.get("diff", {}).get("new", 0) }} baru, {{ summary.get("diff", {}).get("resolved", 0) }} selesai, {{ summary.get("diff", {}).get("persistent", 0) }} masih ada, {{ summary.get("diff", {}).get("reopened", 0) }} muncul kembali.
{% else %}Assessment pertama untuk asset ini.
{% endif %}

## Asset

{% for k, v in asset_info %}- **{{ k }}:** {{ md(v) }}
{% endfor %}

## Temuan Kritis & Tinggi

{% for c in critical %}
### [{{ c.severity.value }}] {{ md(c.title) }}
{% if c.target %}- Target: {{ md(c.target) }}
{% endif %}
{% set f = findings.get(c.finding_id) %}
{% if f %}- Confidence: {{ "%.0f"|format(f.confidence * 100) }}% · pertama terlihat {{ fmt(f.first_seen) }}
{% endif %}
{% if c.recommendation %}- Rekomendasi: {{ md(c.recommendation) }}
{% endif %}

{% else %}Tidak ada.
{% endfor %}

## Peringatan

{% for c in warnings %}- **[{{ c.severity.value }}]** {{ md(c.title) }}{% if c.value %} — {{ md(c.value) }}{% endif %}

{% else %}Tidak ada.
{% endfor %}

## Semua Check

| Check | Status | Hasil |
|---|---|---|
{% for c in checks %}| {{ c.check }} | {{ c.status.value }} | {{ md(c.title) }} |
{% endfor %}

_Temuan malware berstatus SUSPECTED sampai diverifikasi. Tidak ada file yang dihapus otomatis._
"""


def render_html(ctx: dict) -> str:
    return _env.from_string(HTML).render(**ctx)


def render_markdown(ctx: dict) -> str:
    return _md_env.from_string(MARKDOWN).render(**ctx)


def render_json(ctx: dict) -> dict:
    a = ctx["assessment"]
    return {
        "report_generated_at": ctx["generated_at"],
        "asset": {k: str(v) for k, v in ctx["asset_info"]} | {"id": str(ctx["asset"].id)},
        "assessment": {"id": str(a.id), "state": a.state.value,
                       "overall_status": a.overall_status.value if a.overall_status else None,
                       "started_at": ctx["started"], "finished_at": ctx["finished"], "summary": a.summary},
        "checks": [{"check": c.check, "category": c.category.value, "status": c.status.value,
                    "severity": c.severity.value, "title": c.title, "target": c.target, "value": c.value,
                    "evidence": c.evidence, "recommendation": c.recommendation,
                    "finding_id": str(c.finding_id) if c.finding_id else None} for c in ctx["checks"]],
    }
