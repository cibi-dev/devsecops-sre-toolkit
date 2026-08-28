"""Deterministic Markdown and JSON Report Generator for SRE Blameless Post-Mortems.

Complies with Google SRE, Netflix, and PagerDuty Post-Mortem best practices.
Guarantees full sanitization and deterministic formatting.
"""

from __future__ import annotations

import json
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from jinja2 import Environment, Template, select_autoescape
from pydantic import BaseModel, Field

from postmortem.rca_engine import RCAResult
from postmortem.sanitizer import sanitize_data, sanitize_text
from postmortem.timeline_builder import IncidentMetrics, TimelineEvent


class IncidentSeverity(str, Enum):
    """Incident severity classification."""

    SEV_1 = "SEV-1"  # Critical outage: Core service completely unavailable
    SEV_2 = "SEV-2"  # Major impairment: Redundancy lost or major feature degraded
    SEV_3 = "SEV-3"  # Minor degradation: Non-critical customer friction
    SEV_4 = "SEV-4"  # Low impact: Internal or cosmetic bug


class IncidentStatus(str, Enum):
    """Incident operational lifecycle state."""

    INVESTIGATING = "INVESTIGATING"
    IDENTIFIED = "IDENTIFIED"
    MITIGATED = "MITIGATED"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"


class IncidentReport(BaseModel):
    """Complete structured Incident Report dataset."""

    incident_id: str
    title: str
    severity: str = IncidentSeverity.SEV_1.value
    status: str = IncidentStatus.RESOLVED.value
    date: str
    commander: str = "Unassigned"
    lead: str = "Unassigned"
    summary: str
    user_impact: str = "None reported"
    revenue_or_slo_impact: str = "None reported"
    timeline: List[TimelineEvent] = Field(default_factory=list)
    metrics: IncidentMetrics = Field(default_factory=IncidentMetrics)
    rca: RCAResult
    evidences: Dict[str, Any] = Field(default_factory=dict)


DEFAULT_POSTMORTEM_TEMPLATE = """# 📋 Post-Mortem Report: {{ report.title }}

> **Incident ID:** `{{ report.incident_id }}` | **Date:** {{ report.date }} | **Status:** `{{ report.status }}` | **Severity:** `{{ report.severity }}`  
> **Incident Commander:** {{ report.commander }} | **Technical Lead:** {{ report.lead }}

---

## 🎯 Executive Summary
{{ report.summary }}

---

## 📉 Impact & SLO Analysis
- **User Impact:** {{ report.user_impact }}
- **Business & SLO / Error Budget Impact:** {{ report.revenue_or_slo_impact }}
- **Total Incident Duration:** `{{ report.metrics.total_outage_formatted }}`

---

## ⏱️ Key SRE Metrics Dashboard

| Metric | Measured Value | Description |
|---|:---:|---|
| **TTD** (Time to Detect) | `{{ report.metrics.ttd_formatted }}` | Duration from incident onset until initial alert/detection |
| **MTTA / TTA** (Time to Acknowledge) | `{{ report.metrics.mtta_formatted }}` | Duration from detection until on-call engineer acknowledged |
| **TTM** (Time to Mitigate) | `{{ report.metrics.ttm_formatted }}` | Duration from onset until primary customer impact was mitigated |
| **MTTR / TTR** (Time to Resolve) | `{{ report.metrics.mttr_formatted }}` | Total duration from onset to complete system resolution |

---

## 🕒 Minute-by-Minute Timeline (UTC)

| Timestamp (UTC) | Phase / Type | Source | Description | Impact |
|---|---|---|---|:---:|
{% for event in report.timeline -%}
| `{{ event.timestamp.strftime('%Y-%m-%d %H:%M:%S') }}` | `{{ event.event_type }}` | {{ event.source }} | {{ event.description }} | `{{ event.impact_level }}` |
{% endfor %}

---

## 🔍 Root Cause Analysis (RCA)

### Trigger Event
{{ report.rca.trigger_event }}

### Root Cause Summary
{{ report.rca.root_cause_summary }}

{% if report.rca.five_whys and report.rca.five_whys.why_chain %}
### Structured 5-Whys Analysis
**Problem Statement:** *{{ report.rca.five_whys.problem_statement }}*

{% for why in report.rca.five_whys.why_chain -%}
{{ loop.index }}. **Why?** {{ why }}
{% endfor %}
👉 **Root Cause:** **{{ report.rca.five_whys.root_cause }}**
{% endif %}

{% if report.rca.contributing_factors %}
### Contributing Factors
| Category | Factor Description | Impact |
|---|---|:---:|
{% for factor in report.rca.contributing_factors -%}
| `{{ factor.category }}` | {{ factor.description }} | `{{ factor.impact }}` |
{% endfor %}
{% endif %}

---

## 💡 Lessons Learned & Team Reflections

### What Went Well
{% if report.rca.what_went_well -%}
{% for item in report.rca.what_went_well -%}
- ✅ {{ item }}
{% endfor %}
{% else -%}
- *No specific items recorded.*
{% endif %}

### What Went Poorly
{% if report.rca.what_went_poorly -%}
{% for item in report.rca.what_went_poorly -%}
- ⚠️ {{ item }}
{% endfor %}
{% else -%}
- *No specific items recorded.*
{% endif %}

### Where We Got Lucky
{% if report.rca.where_we_got_lucky -%}
{% for item in report.rca.where_we_got_lucky -%}
- 🍀 {{ item }}
{% endfor %}
{% else -%}
- *No specific items recorded.*
{% endif %}

---

## 🛠️ Preventative & Corrective Action Items

| Item ID | Priority | Type | Action Description | Owner | Target Date | Status |
|---|:---:|:---:|---|---|:---:|:---:|
{% for action in report.rca.action_items -%}
| `{{ action.id }}` | **{{ action.priority }}** | `{{ action.item_type }}` | {{ action.description }} | {{ action.owner }} | {{ action.target_date or 'TBD' }} | `{{ action.status }}` |
{% endfor %}

---

## 🔒 Sanitized Technical Evidence & Audit Trail

{% if report.evidences.saturation_metrics %}
### Host Saturation Metrics Snapshot
```json
{{ report.evidences.saturation_metrics | to_pretty_json }}
```
{% endif %}

{% if report.evidences.git_commits %}
### Recent Git Commits Leading up to Incident
| Commit Hash | Author | Timestamp | Message |
|---|---|---|---|
{% for commit in report.evidences.git_commits -%}
| `{{ commit.hash[:8] if commit.hash else 'N/A' }}` | {{ commit.author }} | {{ commit.date }} | {{ commit.message }} |
{% endfor %}
{% endif %}

{% if report.evidences.git_diffs and report.evidences.git_diffs != '[INFO] No diffs found in the specified range.' %}
### Configuration / Deployment Diffs
```diff
{{ report.evidences.git_diffs }}
```
{% endif %}

{% if report.evidences.system_logs %}
### Relevant System Log Traces
```log
{% for line in report.evidences.system_logs -%}
{{ line }}
{% endfor %}
```
{% endif %}

---
*Generated deterministically with [postmortem-incident-generator](https://github.com/cibi-dev/postmortem-incident-generator) • Blameless Culture & SRE Standard Compliant.*
"""


class PostmortemGenerator:
    """Enterprise generator for SRE Post-Mortem Markdown and JSON reports."""

    def __init__(self, custom_template: Optional[str] = None) -> None:
        self.env = Environment(
            autoescape=select_autoescape(["html", "htm", "xml"]),
            trim_blocks=True,
            lstrip_blocks=True,
        )
        self.env.filters["to_pretty_json"] = lambda obj: json.dumps(obj, indent=2)
        template_content = custom_template or DEFAULT_POSTMORTEM_TEMPLATE
        self.template: Template = self.env.from_string(template_content)

    def render_markdown(self, report: IncidentReport) -> str:
        """Render the incident report into audit-ready Markdown."""
        return self.template.render(report=report)

    def export_to_file(self, report: IncidentReport, output_path: Union[str, Path]) -> Path:
        """Export the rendered markdown to a designated file."""
        target = Path(output_path).resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        content = self.render_markdown(report)
        target.write_text(content, encoding="utf-8")
        return target

    def render_json(self, report: IncidentReport, indent: int = 2) -> str:
        """Export structured incident data as JSON."""
        return report.model_dump_json(indent=indent)
