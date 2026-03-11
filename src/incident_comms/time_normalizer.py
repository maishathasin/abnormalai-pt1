from __future__ import annotations

from datetime import datetime
from zoneinfo import ZoneInfo


UTC_TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
PACIFIC_TZ = ZoneInfo("America/Los_Angeles")


def parse_utc_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.strptime(value, UTC_TIME_FORMAT).replace(tzinfo=ZoneInfo("UTC"))


def to_pacific(dt: datetime | None) -> datetime | None:
    if not dt:
        return None
    return dt.astimezone(PACIFIC_TZ)


def format_utc_timestamp(value: str | None, include_date: bool = True) -> str:
    dt = parse_utc_timestamp(value)
    if not dt:
        return "Unknown"
    if include_date:
        return dt.strftime("%B %d, %Y at %H:%M UTC")
    return dt.strftime("%H:%M UTC")


def format_pacific_timestamp(value: str | None, include_date: bool = True) -> str:
    dt = to_pacific(parse_utc_timestamp(value))
    if not dt:
        return "Unknown"
    if include_date:
        return dt.strftime("%b %d, %H:%M %Z")
    return dt.strftime("%H:%M %Z")


def normalize_incident_window(start: str | None, end: str | None) -> dict[str, str | int | None]:
    start_dt = parse_utc_timestamp(start)
    end_dt = parse_utc_timestamp(end)
    if not start_dt or not end_dt:
        return {
            "window_utc": "Unknown",
            "window_pt": "Unknown",
            "duration_minutes": None,
            "started_at_utc": format_utc_timestamp(start),
            "resolved_at_utc": format_utc_timestamp(end),
            "started_at_pt": format_pacific_timestamp(start),
            "resolved_at_pt": format_pacific_timestamp(end),
        }

    start_pt = to_pacific(start_dt)
    end_pt = to_pacific(end_dt)
    duration_minutes = int((end_dt - start_dt).total_seconds() // 60)

    window_utc = (
        f"Between {start_dt.strftime('%B %d, %Y at %H:%M UTC')} and "
        f"{end_dt.strftime('%B %d, %Y at %H:%M UTC')}"
    )

    if start_pt.date() == end_pt.date():
        window_pt = (
            f"{start_pt.strftime('%b %d, %H:%M')} - "
            f"{end_pt.strftime('%H:%M %Z')}"
        )
    else:
        window_pt = (
            f"{start_pt.strftime('%b %d, %H:%M %Z')} - "
            f"{end_pt.strftime('%b %d, %H:%M %Z')}"
        )

    return {
        "window_utc": window_utc,
        "window_pt": window_pt,
        "duration_minutes": duration_minutes,
        "started_at_utc": start_dt.strftime("%B %d, %Y at %H:%M UTC"),
        "resolved_at_utc": end_dt.strftime("%B %d, %Y at %H:%M UTC"),
        "started_at_pt": start_pt.strftime("%b %d, %H:%M %Z"),
        "resolved_at_pt": end_pt.strftime("%b %d, %H:%M %Z"),
    }
