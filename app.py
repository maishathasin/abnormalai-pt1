from __future__ import annotations

import json
import sys
from pathlib import Path

import streamlit as st


ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from incident_comms.generator import generate_draft, parse_generated_update  # noqa: E402
from incident_comms.pipeline import (  # noqa: E402
    build_incident_packet,
    check_draft,
    load_demo_dataset,
    render_internal_narrative,
)
from incident_comms.publisher import publish_update  # noqa: E402
from incident_comms.time_normalizer import normalize_incident_window  # noqa: E402


CACHE_VERSION = "2026-03-10-normalized-time-v2"


st.set_page_config(
    page_title="AI Incident Comms MVP",
    page_icon="🚨",
    layout="wide",
)


@st.cache_data
def get_dataset(cache_version: str) -> dict:
    _ = cache_version
    return load_demo_dataset(ROOT)


@st.cache_data
def get_packet(cache_version: str, update_type: str) -> dict:
    _ = cache_version
    dataset = get_dataset(cache_version)
    packet = build_incident_packet(dataset, update_type)
    return {"dataset": dataset, "packet": packet}


def _reset_generation_state() -> None:
    st.session_state.pop("draft_text", None)
    st.session_state.pop("draft_meta", None)


def _ensure_packet_compatibility(packet):
    if not hasattr(packet, "normalized_time"):
        packet.normalized_time = normalize_incident_window(packet.started_at, packet.ended_at)
    if not hasattr(packet, "source_snapshot") or packet.source_snapshot is None:
        packet.source_snapshot = {}
    packet.source_snapshot.setdefault("public_window_utc", packet.normalized_time["window_utc"])
    packet.source_snapshot.setdefault("public_window_pt", packet.normalized_time["window_pt"])
    packet.source_snapshot.setdefault("duration_minutes", packet.normalized_time["duration_minutes"])
    return packet


if "draft_text" not in st.session_state:
    st.session_state["draft_text"] = ""
if "draft_meta" not in st.session_state:
    st.session_state["draft_meta"] = {}


st.title("AI-Native Incident Communications MVP")
st.caption("Streamlit console for deriving an incident brief, generating a customer-safe draft, and running pre-publish evals.")

with st.sidebar:
    st.subheader("Controls")
    update_type = st.selectbox(
        "Status update type",
        options=["investigating", "identified", "monitoring", "resolved"],
        index=0,
        on_change=_reset_generation_state,
    )
    use_ai = st.toggle("Use live Anthropic generation if key is set", value=True)
    st.markdown("Required env for live generation: `ANTHROPIC_API_KEY`")
    st.markdown("Optional publish envs: `STATUSPAGE_API_KEY`, `STATUSPAGE_PAGE_ID`, `STATUSPAGE_INCIDENT_ID`")
    generate_clicked = st.button("Generate draft", type="primary", use_container_width=True)
    regenerate_clicked = st.button("Regenerate", use_container_width=True)

data = get_packet(CACHE_VERSION, update_type)
dataset = data["dataset"]
packet = _ensure_packet_compatibility(data["packet"])

if generate_clicked or regenerate_clicked:
    previous_draft = st.session_state["draft_text"] if regenerate_clicked and st.session_state["draft_text"] else None
    failed_checks = None
    if previous_draft:
        failed_checks = [
            f"{check.name}: {check.detail}"
            for check in check_draft(packet, previous_draft, update_type)
            if not check.passed
        ]
    result = generate_draft(
        packet=packet,
        update_type=update_type,
        base_path=ROOT,
        examples=dataset["status_examples"] if use_ai else "",
        previous_draft=previous_draft,
        failed_checks=failed_checks,
    )
    st.session_state["draft_text"] = result["draft"]
    st.session_state["draft_meta"] = result


overview_col, metrics_col = st.columns([2, 1])
with overview_col:
    st.subheader("Incident overview")
    st.write(render_internal_narrative(packet))
    st.markdown(f"**Public UTC window:** {packet.normalized_time['window_utc']}")
    st.markdown(f"**Public PT window:** {packet.normalized_time['window_pt']}")
    if packet.source_snapshot.get("final_resolution_pt") and packet.source_snapshot["final_resolution_pt"] != packet.normalized_time["resolved_at_pt"]:
        st.markdown(f"**Final resolution after monitoring:** {packet.source_snapshot['final_resolution_pt']}")
        st.markdown(f"**Full incident duration:** {packet.source_snapshot.get('final_duration_human')}")
with metrics_col:
    st.metric("Severity", packet.severity)
    st.metric("Impact start", packet.normalized_time["started_at_utc"])
    st.metric("Impact end", packet.normalized_time["resolved_at_utc"])
    st.metric("Impact duration", packet.normalized_time["impact_duration_human"])


review_tab, evidence_tab, raw_tab = st.tabs(["Review console", "Evidence and citations", "Raw sources"])

with review_tab:
    left, right = st.columns([3, 2])
    with left:
        st.subheader("Customer-facing draft")
        st.session_state["draft_text"] = st.text_area(
            "Editable status page message",
            value=st.session_state["draft_text"],
            height=220,
            placeholder="Generate a draft to review it here.",
        )
        draft = st.session_state["draft_text"]
        if draft:
            checks = check_draft(packet, draft, update_type)
            passed = sum(1 for check in checks if check.passed)
            st.caption(f"Pre-publish eval score: {passed}/{len(checks)} checks passed")
            for check in checks:
                if check.passed:
                    st.success(f"{check.name}: {check.detail}")
                else:
                    st.error(f"{check.name}: {check.detail}")

            publish_col, copy_col = st.columns(2)
            with publish_col:
                if st.button("Publish update", use_container_width=True):
                    generated_title, generated_message = parse_generated_update(draft)
                    publish_result = publish_update(
                        ROOT,
                        title=generated_title,
                        status=update_type,
                        message=generated_message,
                        metadata={
                            "incident_id": packet.incident_id,
                            "severity": packet.severity,
                            "provider": st.session_state["draft_meta"].get("provider", "unknown"),
                        },
                    )
                    if publish_result["mode"] == "statuspage-api":
                        st.success("Published through Statuspage API.")
                    else:
                        st.warning(f"Saved locally for manual fallback publish at `{publish_result['path']}`.")
            with copy_col:
                st.download_button(
                    label="Download message",
                    data=draft,
                    file_name=f"{update_type}-status-update.txt",
                    use_container_width=True,
                )
    with right:
        st.subheader("Generation metadata")
        meta = st.session_state["draft_meta"]
        if meta:
            if meta.get("error"):
                st.warning(
                    "Live Anthropic generation failed, so the app used the fallback draft instead. "
                    f"{meta.get('error_message') or 'An unexpected provider error occurred.'}"
                )
            st.json(
                {
                    "provider": meta.get("provider"),
                    "model": meta.get("model"),
                    "latency_seconds": meta.get("latency_seconds"),
                    "update_type": update_type,
                    "error_code": meta.get("error_code"),
                    "raw_error": meta.get("error"),
                }
            )
            with st.expander("System prompt", expanded=False):
                st.code((ROOT / "docs" / "system_prompt.md").read_text(), language="markdown")
            with st.expander("Rendered user prompt", expanded=False):
                st.code(meta.get("prompt", ""), language="markdown")
        else:
            st.info("No draft generated yet.")

with evidence_tab:
    st.subheader("Status-scoped source packet")
    for source_name, payload in packet.raw_sources.items():
        with st.expander(source_name, expanded=False):
            st.code(json.dumps(payload, indent=2) if not isinstance(payload, str) else payload, language="markdown" if source_name.endswith(".txt") else "json")

    st.subheader("Structured incident snapshot")
    st.json(packet.source_snapshot)

with raw_tab:
    st.subheader("Sample input archives")
    st.markdown("These are the raw sources the MVP reduces before generation.")
    raw_choice = st.selectbox(
        "View source",
        options=[
            "incident_context.txt",
            "cloudwatch_logs.json",
            "prometheus_metrics.json",
            "pagerduty_incident.json",
            "github_deployments.json",
            "status_page_examples.md",
            "docs/examples.md",
            "docs/system_prompt.md",
            "src/incident_comms/time_normalizer.py",
        ],
    )
    mapping = {
        "incident_context.txt": dataset["incident_context"],
        "cloudwatch_logs.json": json.dumps(dataset["cloudwatch_logs"], indent=2),
        "prometheus_metrics.json": json.dumps(dataset["prometheus_metrics"], indent=2),
        "pagerduty_incident.json": json.dumps(dataset["pagerduty_incident"], indent=2),
        "github_deployments.json": json.dumps(dataset["github_deployments"], indent=2),
        "status_page_examples.md": dataset["status_examples"],
        "docs/examples.md": (ROOT / "docs" / "examples.md").read_text(),
        "docs/system_prompt.md": (ROOT / "docs" / "system_prompt.md").read_text(),
        "src/incident_comms/time_normalizer.py": (ROOT / "src" / "incident_comms" / "time_normalizer.py").read_text(),
    }
    st.code(mapping[raw_choice], language="markdown" if raw_choice.endswith(".md") else "json")
