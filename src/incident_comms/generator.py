from __future__ import annotations

import json
import os
import re
import time
import tomllib
from pathlib import Path
from typing import Any

from anthropic import Anthropic

from incident_comms.pipeline import IncidentPacket, packet_for_generation


def _read_policy_docs(base_path: str | Path) -> dict[str, str]:
    base = Path(base_path)
    return {
        "plan": (base / "docs" / "plan.md").read_text(),
        "security": (base / "docs" / "security.md").read_text(),
        "dataprocessing": (base / "docs" / "dataprocessing.md").read_text(),
        "examples": (base / "docs" / "examples.md").read_text(),
        "system_prompt": (base / "docs" / "system_prompt.md").read_text(),
    }


def _read_local_secret(base_path: str | Path, key: str) -> str | None:
    secrets_path = Path(base_path) / ".streamlit" / "secrets.toml"
    if not secrets_path.exists():
        return None
    with secrets_path.open("rb") as handle:
        data = tomllib.load(handle)
    value = data.get(key)
    return value if isinstance(value, str) and value.strip() else None


def _classify_generation_error(exc: Exception) -> tuple[str, str]:
    error_name = type(exc).__name__
    error_text = str(exc).lower()

    if "credit balance is too low" in error_text or "purchase credits" in error_text:
        return (
            "insufficient_credits",
            "Anthropic rejected the request because the account does not have enough credits.",
        )
    if "authentication" in error_text or "invalid x-api-key" in error_text or "api key" in error_text:
        return (
            "invalid_api_key",
            "Anthropic rejected the request because the API key is invalid or unauthorized.",
        )
    if "rate limit" in error_text or "429" in error_text:
        return (
            "rate_limited",
            "Anthropic rate-limited the request. Please wait and try again.",
        )
    if "apiconnectionerror" in error_name.lower() or "connection error" in error_text:
        return (
            "connection_error",
            "The app could not reach Anthropic. Check network access and try again.",
        )
    if "timeout" in error_text:
        return (
            "timeout",
            "The Anthropic request timed out before a response was returned.",
        )
    if "permission" in error_text or "forbidden" in error_text:
        return (
            "permission_denied",
            "Anthropic denied access to this request or model for the current account.",
        )
    if "not_found_error" in error_text or "model:" in error_text:
        return (
            "model_not_found",
            "Anthropic accepted the API key, but the configured model is not available for this account.",
        )
    return (
        "unknown_error",
        f"Anthropic returned an unexpected error: {type(exc).__name__}.",
    )


def _resolve_model(base_path: str | Path) -> str:
    configured = os.getenv("ANTHROPIC_MODEL")
    if not configured:
        configured = _read_local_secret(base_path, "ANTHROPIC_MODEL")
    return configured or "claude-sonnet-4-6"


def _status_constraints(update_type: str) -> str:
    rules = {
        "investigating": "Acknowledge the issue and customer-visible symptoms. Do not say the issue is fixed, stable, restored, or resolved.",
        "identified": "Say the team understands the issue and is implementing mitigation. Do not say the issue is fixed, stable, restored, or resolved.",
        "monitoring": "Say mitigation has been applied and the team is validating recovery. Do not say the issue is fully resolved unless the status is resolved.",
        "resolved": "Say the issue is resolved and service is stable. Do not say the team is still investigating or implementing mitigation.",
    }
    return rules[update_type]


def _status_output_shape(packet: IncidentPacket, update_type: str) -> str:
    if update_type != "resolved":
        return (
            "Output exactly this shape:\n\n"
            "Title: <short customer-facing incident title>\n"
            "Message:\n"
            "<one or two short paragraphs>\n\n"
            f"{packet.normalized_time['window_pt']}\n\n"
            "Do not include analysis, Q&A, or separators."
        )
    return (
        "Output exactly this shape:\n\n"
        "Title: <short customer-facing incident title>\n"
        "Message:\n"
        "<resolved message paragraphs>\n\n"
        "Summary:\n"
        f"Incident start: {packet.normalized_time['started_at_pt']}\n"
        f"Incident resolution: {packet.normalized_time['final_resolution_pt']}\n"
        f"Total duration: {packet.normalized_time['final_duration_human']}\n"
        "Impact: <one plain-language impact line>\n\n"
        f"{packet.normalized_time['window_pt']}\n\n"
        "Do not include analysis, Q&A, or extra headings before the message."
    )


def _extract_relevant_examples(example_text: str, update_type: str) -> str:
    sections = []
    blocks = example_text.split("\n---\n")
    for block in blocks:
        lower = block.lower()
        if update_type == "investigating" and ("initial update" in lower or "investigating" in lower):
            sections.append(block.strip())
        elif update_type == "identified" and "identified" in lower:
            sections.append(block.strip())
        elif update_type == "monitoring" and "monitoring" in lower:
            sections.append(block.strip())
        elif update_type == "resolved" and "resolved" in lower:
            sections.append(block.strip())
    return "\n\n---\n\n".join(section for section in sections if section)


def _sanitize_generated_draft(text: str, update_type: str) -> str:
    cleaned = text.strip()
    reasoning_markers = [
        "before drafting",
        "required incident questions",
        "what customer-facing functionality was affected?",
        "was the impact degraded performance or a complete outage?",
    ]
    lowered = cleaned.lower()
    if any(marker in lowered for marker in reasoning_markers):
        for separator in ["\n---\n", "\n---", "---\n", "---"]:
            if separator in cleaned:
                cleaned = cleaned.split(separator)[-1].strip()
                break

    for prefix in ["final message:", "status update:", "draft:"]:
        if cleaned.lower().startswith(prefix):
            cleaned = cleaned[len(prefix):].strip()

    if update_type != "resolved":
        cleaned = re.sub(r"\n\s*Summary:\s*.*", "", cleaned, flags=re.IGNORECASE | re.DOTALL).strip()

    return cleaned


def _extract_text_blocks(response: Any) -> str:
    return "".join(
        block.text for block in response.content if getattr(block, "type", None) == "text"
    ).strip()


def _fallback_incident_overview(packet: IncidentPacket) -> dict[str, str]:
    overview = {
        "narrative": (
            f"Status-scoped incident packet for `{packet.update_type}` built from raw incident sources. "
            f"The model should infer customer impact from logs, metrics, PagerDuty, deployments, and incident notes."
        ),
        "public_utc_window": packet.normalized_time["window_utc"],
        "public_pt_window": packet.normalized_time["window_pt"],
        "severity": packet.severity,
        "impact_start": packet.normalized_time["started_at_utc"],
        "impact_end": packet.normalized_time["resolved_at_utc"],
        "impact_duration": packet.normalized_time["impact_duration_human"],
    }
    if (
        packet.source_snapshot.get("final_resolution_pt")
        and packet.source_snapshot["final_resolution_pt"] != packet.normalized_time["resolved_at_pt"]
    ):
        overview["final_resolution"] = packet.source_snapshot["final_resolution_pt"]
        overview["full_duration"] = packet.source_snapshot.get("final_duration_human", "Unknown")
    else:
        overview["final_resolution"] = ""
        overview["full_duration"] = ""
    return overview


def _strip_code_fences(text: str) -> str:
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```[a-zA-Z0-9_-]*\n?", "", cleaned)
        cleaned = re.sub(r"\n?```$", "", cleaned)
    return cleaned.strip()


def _parse_overview_response(text: str, packet: IncidentPacket) -> dict[str, str]:
    fallback = _fallback_incident_overview(packet)
    cleaned = _strip_code_fences(text)
    payload_text = cleaned
    if "{" in cleaned and "}" in cleaned:
        start = cleaned.find("{")
        end = cleaned.rfind("}") + 1
        payload_text = cleaned[start:end]
    try:
        parsed = json.loads(payload_text)
    except json.JSONDecodeError:
        return fallback

    if not isinstance(parsed, dict):
        return fallback

    merged: dict[str, str] = {}
    for key, default_value in fallback.items():
        value = parsed.get(key, default_value)
        if isinstance(value, str) and value.strip():
            merged[key] = value.strip()
        else:
            merged[key] = default_value
    return merged


def ensure_structured_output(packet: IncidentPacket, draft: str, update_type: str) -> str:
    cleaned = draft.strip()
    if not re.search(r"(?im)^title:\s*", cleaned):
        title = packet.title.replace("High latency - ", "").replace("api-gateway", "API Performance Issue")
        cleaned = f"Title: {title}\n\nMessage:\n{cleaned}"
    elif not re.search(r"(?im)^message:\s*", cleaned):
        parts = cleaned.splitlines()
        if parts:
            title_line = parts[0]
            body = "\n".join(parts[1:]).strip()
            cleaned = f"{title_line}\n\nMessage:\n{body}"

    if packet.normalized_time["window_pt"] not in cleaned:
        cleaned = f"{cleaned.rstrip()}\n\n{packet.normalized_time['window_pt']}"

    if update_type != "resolved":
        cleaned = re.sub(r"\n\s*Summary:\s*.*", "", cleaned, flags=re.IGNORECASE | re.DOTALL).strip()
    elif "summary:" not in cleaned.lower():
        cleaned = (
            f"{cleaned.rstrip()}\n\nSummary:\n"
            f"Incident start: {packet.normalized_time['started_at_pt']}\n"
            f"Incident resolution: {packet.normalized_time['final_resolution_pt']}\n"
            f"Total duration: {packet.normalized_time['final_duration_human']}\n"
            "Impact: Customer-facing service impact was observed during the incident window."
        )

    return cleaned.strip()


def parse_generated_update(draft: str) -> tuple[str, str]:
    text = draft.strip()
    title_match = re.search(r"(?im)^title:\s*(.+)$", text)
    message_match = re.search(r"(?is)^message:\s*(.+)$", text)
    title = title_match.group(1).strip() if title_match else "Customer-facing incident update"
    if message_match:
        message = message_match.group(1).strip()
    else:
        message = re.sub(r"(?im)^title:\s*.+$", "", text).strip()
    return title, message


def _fallback_copy(packet: IncidentPacket, update_type: str) -> str:
    if update_type == "investigating":
        return (
            f"Title: {packet.title}\n\n"
            "Message:\n"
            f"Between {packet.normalized_time['started_at_pt']} and {packet.normalized_time['resolved_at_pt']}, "
            f"Abnormal experienced an issue affecting {packet.service}. "
            f"We are investigating customer impact and will share another update as soon as we have more information.\n\n"
            f"{packet.normalized_time['window_pt']}"
        )
    if update_type == "identified":
        return (
            f"Title: {packet.title}\n\n"
            "Message:\n"
            f"Between {packet.normalized_time['started_at_pt']} and {packet.normalized_time['resolved_at_pt']}, "
            f"Abnormal experienced an issue affecting {packet.service}. "
            f"We have identified the issue and are actively implementing mitigation while customer impact continues.\n\n"
            f"{packet.normalized_time['window_pt']}"
        )
    if update_type == "monitoring":
        return (
            f"Title: {packet.title}\n\n"
            "Message:\n"
            f"Between {packet.normalized_time['started_at_pt']} and {packet.normalized_time['resolved_at_pt']}, "
            f"Abnormal experienced an issue affecting {packet.service}. "
            f"Mitigation has been applied and service health is improving. We are monitoring to confirm stability before marking the incident resolved.\n\n"
            f"{packet.normalized_time['window_pt']}"
        )
    return (
        f"Title: {packet.title}\n\n"
        "Message:\n"
        f"Between {packet.normalized_time['started_at_pt']} and {packet.normalized_time['impact_end_pt']}, "
        f"Abnormal experienced an issue affecting {packet.service}. "
        f"Service performance has been restored and remained stable through the monitoring period. "
        f"If you have any questions or continue to experience issues, please contact support at support@abnormalsecurity.com.\n\n"
        "Summary:\n"
        f"Incident start: {packet.normalized_time['started_at_pt']}\n"
        f"Incident resolution: {packet.normalized_time['final_resolution_pt']}\n"
        f"Total duration: {packet.normalized_time['final_duration_human']}\n"
        "Impact: Customer-facing service impact was observed during the incident window.\n\n"
        f"{packet.normalized_time['window_pt']}"
    )


def _build_prompt(
    packet: IncidentPacket,
    update_type: str,
    policies: dict[str, str],
    examples: str,
    previous_draft: str | None = None,
    failed_checks: list[str] | None = None,
) -> str:
    payload = packet_for_generation(packet)
    canonical_examples = _extract_relevant_examples(policies["examples"].strip(), update_type)
    supplemental_examples = examples.strip()
    examples_block = canonical_examples
    if supplemental_examples and supplemental_examples != canonical_examples:
        filtered_supplemental = _extract_relevant_examples(supplemental_examples, update_type)
        if filtered_supplemental and filtered_supplemental != canonical_examples:
            examples_block = f"{canonical_examples}\n\n## Supplemental Archive Examples\n\n{filtered_supplemental}"
    regeneration_block = ""
    if previous_draft:
        problems = "\n".join(f"- {item}" for item in (failed_checks or ["Improve the previous draft while keeping it grounded in the same evidence."]))
        regeneration_block = f"""
<regeneration_context>
Previous draft:
{previous_draft}

Problems to fix:
{problems}

Write a better draft that fixes those issues while staying grounded in the same evidence packet.
</regeneration_context>
"""
    return f"""
You are writing a status page update for customers during a live incident.

Follow these policy documents exactly:

<system_prompt>
{policies["system_prompt"]}
</system_prompt>

<plan>
{policies["plan"]}
</plan>

<security>
{policies["security"]}
</security>

<dataprocessing>
{policies["dataprocessing"]}
</dataprocessing>

Use these style examples for tone and structure. `docs/examples.md` is the canonical reference.
<examples>
{examples_block}
</examples>

Write one customer-facing update for status `{update_type}`.

Requirements:
- Match the tone and public status page style shown in the examples.
- Generate a short customer-facing title for every update.
- Keep it concise and faithful to the examples.
- Use plain language.
- Do not mention internal system names, database names, PR numbers, emails, or engineering names.
- Mention only customer-visible impact and current response stage.
- Always use normalized time from `normalized_time`. Do not emit raw, unnormalized timestamps.
- If status is resolved, include support@abnormalsecurity.com.
- Do not use bullet points.
- Do not output your analysis, chain-of-thought, numbered answers, or phrases like "Before drafting" or "I'll answer the required incident questions."
- Perform the four incident-question answers silently and use them internally.
- Use `normalized_time` from the incident packet as the authoritative normalized time window for the final output.
- Output shape: {_status_output_shape(packet, update_type)}
- Status-specific rule: {_status_constraints(update_type)}

Evidence packet:
{json.dumps(payload, indent=2)}

{regeneration_block}

Return only the final message text.
""".strip()


def _build_overview_prompt(packet: IncidentPacket, policies: dict[str, str]) -> str:
    payload = packet_for_generation(packet)
    return f"""
You are preparing a concise operator-facing incident overview for a Streamlit UI.

Use these policy documents exactly:

<system_prompt>
{policies["system_prompt"]}
</system_prompt>

<security>
{policies["security"]}
</security>

<dataprocessing>
{policies["dataprocessing"]}
</dataprocessing>

Requirements:
- Return valid JSON only. Do not wrap it in markdown.
- Keep every field concise and grounded in the evidence packet.
- Use `normalized_time` as the authoritative source for timestamps and durations.
- Keep the narrative to 2 short sentences.
- Do not mention internal hostnames, PR numbers, database names, or engineering-only details.
- Preserve these exact JSON keys: narrative, public_utc_window, public_pt_window, final_resolution, full_duration, severity, impact_start, impact_end, impact_duration
- If there is no separate final resolution after monitoring, return empty strings for `final_resolution` and `full_duration`.
- `severity` should be a short display label.
- `impact_start`, `impact_end`, and `impact_duration` should be short strings suitable for metric cards.

Evidence packet:
{json.dumps(payload, indent=2)}
""".strip()


def generate_incident_overview(
    packet: IncidentPacket,
    base_path: str | Path,
) -> dict[str, Any]:
    policies = _read_policy_docs(base_path)
    prompt = _build_overview_prompt(packet, policies)
    started = time.perf_counter()
    fallback = _fallback_incident_overview(packet)
    api_key = os.getenv("ANTHROPIC_API_KEY") or _read_local_secret(base_path, "ANTHROPIC_API_KEY")

    if not api_key:
        return {
            "overview": fallback,
            "provider": "fallback-template",
            "latency_seconds": round(time.perf_counter() - started, 2),
            "prompt": prompt,
            "error": None,
            "error_code": None,
            "error_message": None,
            "model": None,
        }

    client = Anthropic(api_key=api_key)
    try:
        model_used = _resolve_model(base_path)
        response = client.messages.create(
            model=model_used,
            max_tokens=350,
            temperature=0.1,
            system=policies["system_prompt"],
            messages=[{"role": "user", "content": prompt}],
        )
        overview = _parse_overview_response(_extract_text_blocks(response), packet)
    except Exception as exc:
        error_code, error_message = _classify_generation_error(exc)
        return {
            "overview": fallback,
            "provider": "fallback-template",
            "latency_seconds": round(time.perf_counter() - started, 2),
            "prompt": prompt,
            "error": f"{type(exc).__name__}: {exc}",
            "error_code": error_code,
            "error_message": error_message,
            "model": None,
        }

    return {
        "overview": overview,
        "provider": "anthropic",
        "latency_seconds": round(time.perf_counter() - started, 2),
        "prompt": prompt,
        "error": None,
        "error_code": None,
        "error_message": None,
        "model": model_used,
    }


def generate_draft(
    packet: IncidentPacket,
    update_type: str,
    base_path: str | Path,
    examples: str,
    previous_draft: str | None = None,
    failed_checks: list[str] | None = None,
) -> dict[str, Any]:
    policies = _read_policy_docs(base_path)
    prompt = _build_prompt(packet, update_type, policies, examples, previous_draft=previous_draft, failed_checks=failed_checks)
    started = time.perf_counter()
    api_key = os.getenv("ANTHROPIC_API_KEY") or _read_local_secret(base_path, "ANTHROPIC_API_KEY")

    if not api_key:
        draft = _fallback_copy(packet, update_type)
        return {
            "draft": draft,
            "provider": "fallback-template",
            "latency_seconds": round(time.perf_counter() - started, 2),
            "prompt": prompt,
            "error": None,
            "error_code": None,
            "error_message": None,
        }

    client = Anthropic(api_key=api_key)
    try:
        model_used = _resolve_model(base_path)
        response = client.messages.create(
            model=model_used,
            max_tokens=int(os.getenv("ANTHROPIC_MAX_TOKENS", "500")),
            temperature=0.1,
            system=policies["system_prompt"],
            messages=[{"role": "user", "content": prompt}],
        )
        draft = _extract_text_blocks(response)
        draft = _sanitize_generated_draft(draft, update_type)
        draft = ensure_structured_output(packet, draft, update_type)
    except Exception as exc:
        error_code, error_message = _classify_generation_error(exc)
        draft = ensure_structured_output(packet, _fallback_copy(packet, update_type), update_type)
        return {
            "draft": draft,
            "provider": "fallback-template",
            "latency_seconds": round(time.perf_counter() - started, 2),
            "prompt": prompt,
            "error": f"{type(exc).__name__}: {exc}",
            "error_code": error_code,
            "error_message": error_message,
            "model": None,
        }

    return {
        "draft": ensure_structured_output(packet, draft or _fallback_copy(packet, update_type), update_type),
        "provider": "anthropic",
        "latency_seconds": round(time.perf_counter() - started, 2),
        "prompt": prompt,
        "error": None,
        "error_code": None,
        "error_message": None,
        "model": model_used,
    }
