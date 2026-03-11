from __future__ import annotations

import json
import re
import zipfile
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

from incident_comms.time_normalizer import (
    format_utc_timestamp,
    parse_utc_timestamp,
)


UTC = ZoneInfo("UTC")
PACIFIC = ZoneInfo("America/Los_Angeles")
INTERNAL_PATTERNS = [
    r"rds-prod-main",
    r"PR\s*#\d+",
    r"\b[a-f0-9]{6,40}\b",
    r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
    r"(?<![A-Za-z0-9._%+-])@[a-zA-Z0-9._-]+",
]
ALLOWED_EXTERNAL_EMAILS = {"support@abnormalsecurity.com"}
STATUS_KEYWORDS = {
    "identified": ["identified", "mitigation", "rollback", "implementing", "found it", "fix"],
    "monitoring": ["monitoring", "stable", "returning to normal", "recovered", "rollback complete", "improving"],
    "resolved": ["resolved", "marking incident as resolved", "fully functional", "restored"],
}
STATUS_FORBIDDEN_TERMS = {
    "investigating": ["resolved", "restored", "stable", "fully functional", "monitoring"],
    "identified": ["resolved", "restored", "fully functional"],
    "monitoring": ["investigating", "looking into", "fully resolved"],
    "resolved": ["investigating", "looking into", "implementing mitigation"],
}


@dataclass
class IncidentPacket:
    incident_id: str
    title: str
    severity: str
    service: str
    update_type: str
    started_at: str | None
    ended_at: str | None
    normalized_time: dict[str, Any]
    raw_sources: dict[str, Any]
    source_snapshot: dict[str, Any]
    analysis_questions: list[str]


@dataclass
class EvalCheck:
    name: str
    passed: bool
    detail: str


def _read_zip_texts(archive_path: Path) -> dict[str, str]:
    contents: dict[str, str] = {}
    with zipfile.ZipFile(archive_path) as archive:
        for name in archive.namelist():
            if not name or name.endswith("/"):
                continue
            contents[name] = archive.read(name).decode("utf-8")
    return contents


def load_demo_dataset(base_path: str | Path) -> dict[str, Any]:
    base = Path(base_path)
    raw_texts = _read_zip_texts(base / "data.zip")
    examples = _read_zip_texts(base / "examples.zip")
    return {
        "incident_context": raw_texts["incident_context.txt"],
        "cloudwatch_logs": json.loads(raw_texts["cloudwatch_logs.json"]),
        "prometheus_metrics": json.loads(raw_texts["prometheus_metrics.json"]),
        "pagerduty_incident": json.loads(raw_texts["pagerduty_incident.json"]),
        "github_deployments": json.loads(raw_texts["github_deployments.json"]),
        "readme": raw_texts["README.md"],
        "status_examples": examples["status_page_examples.md"],
    }


def _mask_internal_text(text: str) -> str:
    masked = text
    for pattern in INTERNAL_PATTERNS:
        masked = re.sub(pattern, "[redacted]", masked)
    return masked


def _to_iso(dt: datetime | None) -> str | None:
    if not dt:
        return None
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _format_duration_minutes(total_minutes: int | None) -> str:
    if total_minutes is None:
        return "Unknown"
    hours, minutes = divmod(total_minutes, 60)
    if hours and minutes:
        hour_label = "hour" if hours == 1 else "hours"
        return f"{hours} {hour_label} {minutes} mins"
    if hours:
        hour_label = "hour" if hours == 1 else "hours"
        return f"{hours} {hour_label}"
    return f"{minutes} mins"


def _parse_context_started_at_display_pt(context: str) -> datetime | None:
    match = re.search(
        r"Started:\s*([A-Za-z]+ \d{1,2}, \d{4}) around (\d{1,2}:\d{2} [AP]M) Pacific Time",
        context,
    )
    if not match:
        return None
    return datetime.strptime(f"{match.group(1)} {match.group(2)}", "%B %d, %Y %I:%M %p").replace(tzinfo=PACIFIC)


def _parse_context_started_at_aligned_utc(context: str) -> datetime | None:
    started_pt = _parse_context_started_at_display_pt(context)
    if not started_pt:
        return None
    return started_pt.replace(tzinfo=UTC)


def _parse_context_events(context: str) -> list[tuple[datetime, datetime, str]]:
    started_pt = _parse_context_started_at_display_pt(context)
    started_utc = _parse_context_started_at_aligned_utc(context)
    if not started_pt or not started_utc:
        return []
    local_date = started_pt.date()
    events: list[tuple[datetime, datetime, str]] = []
    for line in context.splitlines():
        match = re.match(r"\[(\d{1,2}:\d{2} [AP]M)\]\s*(.*)", line)
        if not match:
            continue
        pt_dt = datetime.strptime(match.group(1), "%I:%M %p").replace(
            year=local_date.year,
            month=local_date.month,
            day=local_date.day,
            tzinfo=PACIFIC,
        )
        aligned_utc = pt_dt.replace(tzinfo=UTC)
        events.append((aligned_utc, pt_dt, match.group(2).strip()))
    return events


def _detect_metric_anomaly_time(metrics: dict[str, Any]) -> datetime | None:
    candidates: list[datetime] = []
    for metric in metrics.get("metrics", []):
        values = metric.get("values", [])
        if len(values) < 2:
            continue
        baseline_values = [float(point["value"]) for point in values[:2]]
        baseline = sum(baseline_values) / len(baseline_values)
        for point in values[2:]:
            value = float(point["value"])
            if baseline == 0:
                if value > 0:
                    parsed = parse_utc_timestamp(point["timestamp"])
                    if parsed:
                        candidates.append(parsed)
                    break
                continue
            if value >= baseline * 3:
                parsed = parse_utc_timestamp(point["timestamp"])
                if parsed:
                    candidates.append(parsed)
                break
    return min(candidates) if candidates else None


def _extract_incident_start(raw: dict[str, Any]) -> datetime | None:
    candidates: list[datetime] = []
    error_logs = [
        parse_utc_timestamp(log["timestamp"])
        for log in raw["cloudwatch_logs"].get("logs", [])
        if log.get("level") == "ERROR"
    ]
    candidates.extend([dt for dt in error_logs if dt])
    metric_anomaly = _detect_metric_anomaly_time(raw["prometheus_metrics"])
    if metric_anomaly:
        candidates.append(metric_anomaly)
    pd_created = parse_utc_timestamp(raw["pagerduty_incident"]["incident"].get("created_at"))
    if pd_created:
        candidates.append(pd_created)
    context_started = _parse_context_started_at_aligned_utc(raw["incident_context"])
    if context_started:
        candidates.append(context_started)
    return min(candidates) if candidates else None


def _extract_final_resolved_time(raw: dict[str, Any]) -> datetime | None:
    incident = raw["pagerduty_incident"]["incident"]
    candidates: list[datetime] = []
    resolved = parse_utc_timestamp(incident.get("resolved_at"))
    if resolved:
        candidates.append(resolved)
    for event_dt, _, detail in _parse_context_events(raw["incident_context"]):
        if any(keyword in detail.lower() for keyword in STATUS_KEYWORDS["resolved"]):
            candidates.append(event_dt)
    return max(candidates) if candidates else None


def _extract_impact_end_time(raw: dict[str, Any], started_at: datetime | None) -> datetime | None:
    candidates: list[datetime] = []

    for event_dt, _, detail in _parse_context_events(raw["incident_context"]):
        lower = detail.lower()
        if started_at and event_dt < started_at:
            continue
        if any(marker in lower for marker in ["rollback complete", "returning to normal", "recovered"]):
            candidates.append(event_dt)

    for log in raw["cloudwatch_logs"].get("logs", []):
        if log.get("level") == "INFO" and "recovered" in log.get("message", "").lower():
            parsed = parse_utc_timestamp(log["timestamp"])
            if parsed and (not started_at or parsed >= started_at):
                candidates.append(parsed)

    for metric in raw["prometheus_metrics"].get("metrics", []):
        if metric.get("metric_name") == "http_request_duration_seconds" and metric.get("labels", {}).get("quantile") == "0.99":
            for point in metric.get("values", []):
                parsed = parse_utc_timestamp(point["timestamp"])
                if not parsed or (started_at and parsed < started_at):
                    continue
                value = float(point["value"])
                if value <= 0.25:
                    candidates.append(parsed)
                    break
        if metric.get("metric_name") != "http_requests_total" or metric.get("labels", {}).get("status") != "500":
            continue
        for point in metric.get("values", []):
            parsed = parse_utc_timestamp(point["timestamp"])
            if not parsed or (started_at and parsed < started_at):
                continue
            value = float(point["value"])
            if value == 0:
                candidates.append(parsed)
                break

    return min(candidates) if candidates else None


def _extract_milestones(raw: dict[str, Any]) -> dict[str, datetime]:
    milestones: dict[str, datetime] = {}
    for event_dt, _, detail in _parse_context_events(raw["incident_context"]):
        lower = detail.lower()
        for status, keywords in STATUS_KEYWORDS.items():
            if status in milestones:
                continue
            if any(keyword in lower for keyword in keywords):
                milestones[status] = event_dt
    return milestones


def _select_cutoff(update_type: str, start: datetime | None, resolved: datetime | None, milestones: dict[str, datetime]) -> datetime | None:
    if not start:
        return resolved
    if update_type == "investigating":
        return min(filter(None, [milestones.get("identified"), milestones.get("monitoring"), resolved, start + timedelta(minutes=15)]))
    if update_type == "identified":
        return min(filter(None, [milestones.get("monitoring"), milestones.get("resolved"), resolved, start + timedelta(minutes=35)]))
    if update_type == "monitoring":
        return min(filter(None, [milestones.get("resolved"), resolved, start + timedelta(minutes=90)]))
    return resolved


def _filter_context_by_cutoff(context: str, cutoff: datetime | None) -> str:
    if not cutoff:
        return context
    started = _parse_context_started_at_display_pt(context)
    local_date = started.date() if started else None
    lines: list[str] = []
    for line in context.splitlines():
        match = re.match(r"\[(\d{1,2}:\d{2} [AP]M)\]\s*(.*)", line)
        if match and local_date:
            aligned_utc = datetime.strptime(match.group(1), "%I:%M %p").replace(
                year=local_date.year,
                month=local_date.month,
                day=local_date.day,
                tzinfo=UTC,
            )
            if aligned_utc <= cutoff:
                lines.append(line)
            continue
        lines.append(line)
    return "\n".join(lines)


def _build_public_time_window(
    raw: dict[str, Any],
    impact_start_utc: datetime | None,
    public_end_utc: datetime | None,
) -> dict[str, Any]:
    start_pt = _parse_context_started_at_display_pt(raw["incident_context"])
    start_utc = _parse_context_started_at_aligned_utc(raw["incident_context"])
    end_pt = None
    end_utc = None
    if public_end_utc:
        context_events = _parse_context_events(raw["incident_context"])
        matching_context = [(aligned_utc, pt_dt) for aligned_utc, pt_dt, _ in context_events if aligned_utc <= public_end_utc]
        if matching_context:
            end_utc, end_pt = matching_context[-1]

    if not start_pt and impact_start_utc:
        start_pt = impact_start_utc.astimezone(PACIFIC)
    if not start_utc:
        start_utc = impact_start_utc
    if not end_pt and public_end_utc:
        end_pt = public_end_utc.astimezone(PACIFIC)
    if not end_utc:
        end_utc = public_end_utc

    if not start_pt or not end_pt or not start_utc or not end_utc:
        return {
            "window_utc": "Unknown",
            "window_pt": "Unknown",
            "duration_minutes": None,
            "started_at_utc": format_utc_timestamp(_to_iso(start_utc)),
            "resolved_at_utc": format_utc_timestamp(_to_iso(end_utc)),
            "started_at_pt": start_pt.strftime("%b %d, %I:%M %p %Z") if start_pt else "Unknown",
            "resolved_at_pt": end_pt.strftime("%b %d, %I:%M %p %Z") if end_pt else "Unknown",
            "final_resolution_pt": "Unknown",
        }

    final_resolution_pt = None
    final_resolution_utc = None
    for _, pt_dt, detail in _parse_context_events(raw["incident_context"]):
        if "marking incident as resolved" in detail.lower():
            final_resolution_pt = pt_dt
            final_resolution_utc = pt_dt.replace(tzinfo=UTC)
            break

    if not final_resolution_pt:
        final_resolution_pt = end_pt
    if not final_resolution_utc:
        final_resolution_utc = end_utc

    duration_minutes = int((end_pt - start_pt).total_seconds() // 60)
    final_duration_minutes = int((final_resolution_pt - start_pt).total_seconds() // 60)
    return {
        "window_utc": (
            f"Between {format_utc_timestamp(_to_iso(start_utc))} and "
            f"{format_utc_timestamp(_to_iso(end_utc))}"
        ),
        "window_pt": (
            f"{start_pt.strftime('%b %d, %I:%M %p %Z')} - "
            f"{end_pt.strftime('%I:%M %p %Z')}"
        ),
        "duration_minutes": duration_minutes,
        "duration_human": _format_duration_minutes(duration_minutes),
        "started_at_utc": format_utc_timestamp(_to_iso(start_utc)),
        "resolved_at_utc": format_utc_timestamp(_to_iso(end_utc)),
        "started_at_pt": start_pt.strftime("%b %d, %I:%M %p %Z"),
        "resolved_at_pt": end_pt.strftime("%b %d, %I:%M %p %Z"),
        "impact_duration_minutes": duration_minutes,
        "impact_duration_human": _format_duration_minutes(duration_minutes),
        "impact_end_pt": end_pt.strftime("%b %d, %I:%M %p %Z"),
        "impact_end_utc": format_utc_timestamp(_to_iso(end_utc)),
        "final_resolution_pt": final_resolution_pt.strftime("%b %d, %I:%M %p %Z"),
        "final_resolution_utc": format_utc_timestamp(_to_iso(final_resolution_utc)),
        "final_duration_minutes": final_duration_minutes,
        "final_duration_human": _format_duration_minutes(final_duration_minutes),
    }


def _filter_metrics_by_cutoff(metrics: dict[str, Any], cutoff: datetime | None) -> dict[str, Any]:
    if not cutoff:
        return metrics
    filtered = {"metrics": []}
    for metric in metrics.get("metrics", []):
        points = [
            point
            for point in metric.get("values", [])
            if (parse_utc_timestamp(point["timestamp"]) or datetime.max.replace(tzinfo=UTC)) <= cutoff
        ]
        if points:
            filtered["metrics"].append(
                {
                    "metric_name": metric.get("metric_name"),
                    "labels": metric.get("labels", {}),
                    "values": points,
                }
            )
    return filtered


def _filter_logs_by_cutoff(logs: dict[str, Any], cutoff: datetime | None) -> dict[str, Any]:
    if not cutoff:
        return logs
    return {
        "logs": [
            log
            for log in logs.get("logs", [])
            if (parse_utc_timestamp(log["timestamp"]) or datetime.max.replace(tzinfo=UTC)) <= cutoff
        ]
    }


def _filter_deployments_by_cutoff(deployments: dict[str, Any], cutoff: datetime | None) -> dict[str, Any]:
    if not cutoff:
        return deployments
    return {
        "deployments": [
            deployment
            for deployment in deployments.get("deployments", [])
            if (parse_utc_timestamp(deployment["timestamp"]) or datetime.max.replace(tzinfo=UTC)) <= cutoff
        ]
    }


def _filter_pagerduty_by_cutoff(pagerduty: dict[str, Any], cutoff: datetime | None, update_type: str) -> dict[str, Any]:
    payload = deepcopy(pagerduty)
    incident = payload["incident"]
    if cutoff:
        incident["timeline"] = [
            event
            for event in incident.get("timeline", [])
            if (parse_utc_timestamp(event["timestamp"]) or datetime.max.replace(tzinfo=UTC)) <= cutoff
        ]
        if incident.get("acknowledged_at") and (parse_utc_timestamp(incident["acknowledged_at"]) or datetime.max.replace(tzinfo=UTC)) > cutoff:
            incident["acknowledged_at"] = None
        if incident.get("resolved_at") and update_type != "resolved":
            incident["resolved_at"] = None
    incident["status"] = update_type
    return payload


def build_incident_packet(raw: dict[str, Any], update_type: str) -> IncidentPacket:
    incident = raw["pagerduty_incident"]["incident"]
    started_at = _extract_incident_start(raw)
    impact_end_at = _extract_impact_end_time(raw, started_at)
    final_resolved_at = _extract_final_resolved_time(raw)
    milestones = _extract_milestones(raw)
    cutoff = _select_cutoff(update_type, started_at, final_resolved_at, milestones)
    public_end_at = (impact_end_at or final_resolved_at) if update_type == "resolved" else (cutoff or impact_end_at or final_resolved_at)
    normalized_time = _build_public_time_window(raw, started_at, public_end_at)

    raw_sources = {
        "incident_context.txt": _filter_context_by_cutoff(raw["incident_context"], cutoff),
        "cloudwatch_logs.json": _filter_logs_by_cutoff(raw["cloudwatch_logs"], cutoff),
        "prometheus_metrics.json": _filter_metrics_by_cutoff(raw["prometheus_metrics"], cutoff),
        "pagerduty_incident.json": _filter_pagerduty_by_cutoff(raw["pagerduty_incident"], cutoff, update_type),
        "github_deployments.json": _filter_deployments_by_cutoff(raw["github_deployments"], cutoff),
    }

    return IncidentPacket(
        incident_id=incident.get("id", "unknown-incident"),
        title=incident.get("title", "Customer-facing incident"),
        severity=incident.get("severity", "Unknown"),
        service=incident.get("service", "Unknown service"),
        update_type=update_type,
        started_at=_to_iso(started_at),
        ended_at=_to_iso(public_end_at),
        normalized_time=normalized_time,
        raw_sources=raw_sources,
        source_snapshot={
            "logs_count": len(raw_sources["cloudwatch_logs.json"].get("logs", [])),
            "metric_series_count": len(raw_sources["prometheus_metrics.json"].get("metrics", [])),
            "deployments_count": len(raw_sources["github_deployments.json"].get("deployments", [])),
            "pagerduty_timeline_events": len(raw_sources["pagerduty_incident.json"]["incident"].get("timeline", [])),
            "public_window_utc": normalized_time["window_utc"],
            "public_window_pt": normalized_time["window_pt"],
            "duration_minutes": normalized_time["duration_minutes"],
            "duration_human": normalized_time["duration_human"],
            "impact_end_utc": _to_iso(impact_end_at),
            "impact_end_pt": normalized_time["impact_end_pt"],
            "final_resolution_utc": _to_iso(final_resolved_at),
            "final_resolution_pt": normalized_time["final_resolution_pt"],
            "final_duration_minutes": normalized_time["final_duration_minutes"],
            "final_duration_human": normalized_time["final_duration_human"],
        },
        analysis_questions=[
            "What customer-facing functionality was affected?",
            "Was the impact degraded performance or a complete outage?",
            "When did impact start and end in Pacific Time?",
            "Were all customers affected or only a subset?",
        ],
    )


def packet_for_generation(packet: IncidentPacket) -> dict[str, Any]:
    return {
        "incident_id": packet.incident_id,
        "title": packet.title,
        "severity": packet.severity,
        "service": packet.service,
        "update_type": packet.update_type,
        "started_at": format_utc_timestamp(packet.started_at),
        "ended_at": format_utc_timestamp(packet.ended_at),
        "normalized_time": packet.normalized_time,
        "analysis_questions": packet.analysis_questions,
        "source_snapshot": packet.source_snapshot,
        "raw_sources": packet.raw_sources,
    }


def render_internal_narrative(packet: IncidentPacket) -> str:
    return (
        f"Status-scoped incident packet for `{packet.update_type}` built from raw incident sources. "
        f"The model should infer customer impact from logs, metrics, PagerDuty, deployments, and incident notes. "
        f"Public time window: {packet.normalized_time['window_utc']} ({packet.normalized_time['window_pt']})."
    )


def check_draft(packet: IncidentPacket, draft: str, update_type: str) -> list[EvalCheck]:
    lower = draft.lower()
    checks: list[EvalCheck] = []

    leaked_terms = []
    for pattern in INTERNAL_PATTERNS:
        matches = re.findall(pattern, draft, flags=re.IGNORECASE)
        leaked_terms.extend([match for match in matches if match.lower() not in ALLOWED_EXTERNAL_EMAILS])
    checks.append(
        EvalCheck(
            name="Leakage",
            passed=not leaked_terms,
            detail="No internal-only identifiers detected." if not leaked_terms else f"Detected internal detail(s): {', '.join(sorted(set(leaked_terms)))}",
        )
    )

    words = len(draft.split())
    checks.append(
        EvalCheck(
            name="Brevity",
            passed=35 <= words <= 170,
            detail=f"Draft length is {words} words.",
        )
    )

    unsupported_phrases = [phrase for phrase in ["root cause", "PR #", "database connection pool", "commit", "rds-prod-main"] if phrase.lower() in lower]
    checks.append(
        EvalCheck(
            name="Role adherence",
            passed=not unsupported_phrases,
            detail="Draft stays customer-facing." if not unsupported_phrases else f"Draft exposed internal framing: {', '.join(unsupported_phrases)}",
        )
    )

    expected_terms = {
        "investigating": ["investigating", "aware", "looking into"],
        "identified": ["identified", "implementing", "mitigation"],
        "monitoring": ["monitoring", "improving", "returning to normal"],
        "resolved": ["resolved", "restored", "stable", "normal"],
    }
    forbidden = STATUS_FORBIDDEN_TERMS[update_type]
    has_expected = any(term in lower for term in expected_terms[update_type])
    has_forbidden = any(term in lower for term in forbidden)
    checks.append(
        EvalCheck(
            name="Status alignment",
            passed=has_expected and not has_forbidden,
            detail=(
                f"Draft {'matches' if has_expected and not has_forbidden else 'does not clearly match'} the {update_type} state."
                if not has_forbidden
                else f"Draft uses terms that conflict with `{update_type}` status."
            ),
        )
    )

    impact_match = any(term in lower for term in ["api", "response", "request", "performance", "timeout", "delay", "portal", "email"])
    checks.append(
        EvalCheck(
            name="Customer impact clarity",
            passed=impact_match,
            detail="Draft explains customer-visible impact." if impact_match else "Draft should say more clearly what customers experienced.",
        )
    )

    time_match = packet.normalized_time["window_pt"] in draft or "between" in lower
    checks.append(
        EvalCheck(
            name="Time normalization",
            passed=time_match,
            detail="Draft includes a normalized incident time window." if time_match else "Draft should include a normalized customer-facing time window.",
        )
    )

    return checks
