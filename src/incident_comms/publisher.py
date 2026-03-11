from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests


def publish_update(
    base_path: str | Path,
    title: str,
    status: str,
    message: str,
    metadata: dict[str, Any],
) -> dict[str, Any]:
    api_key = os.getenv("STATUSPAGE_API_KEY")
    page_id = os.getenv("STATUSPAGE_PAGE_ID")
    incident_id = os.getenv("STATUSPAGE_INCIDENT_ID")

    payload = {
        "title": title,
        "status": status,
        "body": message,
        "metadata": metadata,
        "published_at": datetime.now(timezone.utc).isoformat(),
    }

    if api_key and page_id and incident_id:
        response = requests.post(
            f"https://api.statuspage.io/v1/pages/{page_id}/incidents/{incident_id}/incident_updates",
            headers={
                "Authorization": f"OAuth {api_key}",
                "Content-Type": "application/json",
            },
            json={
                "incident_update": {
                    "body": message,
                    "status": status,
                    "wants_twitter_update": False,
                    "deliver_notifications": False,
                }
            },
            timeout=20,
        )
        if response.ok:
            payload["response"] = response.json()
            return {"published": True, "mode": "statuspage-api", "payload": payload}
        payload["response"] = {
            "status_code": response.status_code,
            "body": response.text,
        }

    artifacts_dir = Path(base_path) / "artifacts"
    artifacts_dir.mkdir(exist_ok=True)
    output_file = artifacts_dir / "published_updates.jsonl"
    with output_file.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload) + "\n")
    return {
        "published": True,
        "mode": "local-fallback",
        "payload": payload,
        "path": str(output_file),
    }
