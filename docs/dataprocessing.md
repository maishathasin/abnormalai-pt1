# Data Processing Notes

## Inputs

The MVP reads incident evidence from the provided archives:

- `incident_context.txt` for incident channel context and responder notes
- `pagerduty_incident.json` for lifecycle and severity
- `prometheus_metrics.json` for latency, error, and pool utilization trends
- `cloudwatch_logs.json` for supporting error evidence
- `github_deployments.json` for deployment timing

## Usage For Communications

Deployment timing helps identify likely root cause and incident sequencing, but technical details should be abstracted for customer communications. For example, say "a recent configuration change" rather than "increased HTTP timeout from 10s to 30s."

## Reduction Strategy

The app does not send raw technical evidence directly to the model. It first builds a compact internal incident brief with:

- incident metadata
- a normalized timeline
- a normalized public incident window in UTC and Pacific time
- likely customer symptoms
- service impact summary
- notable operational changes
- citations back to the original source evidence

## Time Normalization

Time normalization is handled in `src/incident_comms/time_normalizer.py`.

The normalizer converts raw UTC timestamps into:

- a public UTC incident window for the opening sentence
- a Pacific time range for the final line of the status update
- normalized start and resolution timestamps for reviewer context

This makes the generated copy look more like public status page history rather than raw observability output.

## Incident Start And End Rules

The incident start time is the earliest credible signal across the available evidence. Use the earliest of:

- the first `ERROR` in `cloudwatch_logs.json`
- the first meaningful latency spike in `prometheus_metrics.json`
- the PagerDuty trigger time
- any timestamp mentioned in `incident_context.txt`

Do not use the PagerDuty trigger as the only source of truth.

The incident end time should reflect when customer impact materially stopped or when the service was confirmed stable, based on the strongest available combination of metrics, logs, incident notes, and PagerDuty resolution timing.

## Safety Strategy

Internal identifiers are masked before generation. The model receives customer-safe summaries plus short evidence snippets rather than full raw logs.

## Usage Tips For Incident Communications

### Derive Customer Impact

Use the technical signals to determine:

- What functionality was affected
- How severe the impact was
- When the issue started and ended
- Which customers or regions were likely impacted

### Cross-Reference Timestamps

The incident timeline spans multiple data sources. Look for correlated events across logs, metrics, deployments, and incident notes to build a complete picture.

### Parse ISO 8601 Timestamps

Raw timestamps arrive in UTC. Normalize them into customer-facing UTC windows and Pacific Time display ranges before generating status-page-ready language.

### Translate Technical Signals Into Customer Language

Use customer-facing abstractions instead of internal implementation wording.

- "Database connection pool exhausted" becomes "API performance degradation"
- "p99 latency 15s" becomes "significantly slower response times"
- "500 errors" becomes "intermittent service errors"

### Filter By Severity

Not all technical details belong in customer communications. Prioritize:

- What customers experienced
- Duration and scope of the impact
- Current resolution status
- What happens next

### Handle Missing Fields

Some records may be partial or omit optional fields such as `diff_snippet`. The system should handle missing data gracefully and avoid filling gaps with speculation.

If a field is missing or null, infer what you reasonably can from the other available fields. Do not error or leave obvious gaps when the surrounding evidence supports a safe conclusion.

## Required Incident Questions

Before writing the final status update, answer these questions from the incident data:

1. What customer-facing functionality was affected?
2. Was the impact degraded performance or a complete outage?
3. When did impact start and end in Pacific Time?
4. Were all customers affected or only a subset?

Then use those answers to write the status update.

## Customer-Relevant Change Detection

The MVP treats these as externally meaningful changes:

- issue detected and acknowledged
- issue understood well enough to state customer impact
- mitigation applied and customer symptoms improving
- service stable long enough to resolve
