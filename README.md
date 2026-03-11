# AI-Native Incident Communications MVP

This repository contains a Streamlit MVP for generating customer-facing incident status updates from the anonymized incident data provided in `data.zip` and `examples.zip`.

## What it does

The app loads raw incident evidence, builds an internal incident brief, generates a customer-safe status page update, shows source citations, runs pre-publish eval checks, and supports either direct Statuspage publishing or a local manual fallback.

## Features

- Multi-source ingestion from the provided incident archives
- Internal incident brief derived from metrics, logs, deployment timing, and incident context
- Customer-facing draft generation with policy grounding
- Human-in-the-loop editing and approval
- Pre-publish eval checks for leakage, brevity, role adherence, status alignment, and customer impact clarity
- Local publish fallback plus optional Statuspage API integration

## Project structure

- `app.py`: Streamlit application
- `src/incident_comms/pipeline.py`: ingestion, reduction, and eval logic
- `src/incident_comms/generator.py`: live Claude generation and deterministic fallback
- `src/incident_comms/publisher.py`: local fallback publishing and optional Statuspage integration
- `docs/plan.md`: communication policy
- `docs/security.md`: leakage and safety rules
- `docs/dataprocessing.md`: data reduction strategy

## Local setup

1. Create and activate a virtual environment.
2. Install dependencies.
3. Run the app.

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
streamlit run app.py
```

## Environment variables

### Optional live generation

- `ANTHROPIC_API_KEY`
- `ANTHROPIC_MODEL` default: `claude-sonnet-4-6`

If no Anthropic key is set, the app falls back to a deterministic template generator so the full demo still works.

### Optional Statuspage publishing

- `STATUSPAGE_API_KEY`
- `STATUSPAGE_PAGE_ID`
- `STATUSPAGE_INCIDENT_ID`

If these are not set, pressing publish writes the approved update to `artifacts/published_updates.jsonl`.

## Run tests

```bash
python3 -m unittest tests.test_pipeline
```

## Deploy to Streamlit Community Cloud

1. Push this repo to GitHub.
2. In Streamlit Community Cloud, create a new app from the repo and set the main file path to `app.py`.
3. Add secrets for `ANTHROPIC_API_KEY`, `ANTHROPIC_MODEL=claude-sonnet-4-6`, and optionally the Statuspage variables.
4. Deploy.

The MVP is designed to stay demoable even without secrets by using the built-in fallback generator and local publish path.
