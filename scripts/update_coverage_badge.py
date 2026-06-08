from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate an SVG coverage badge from a coverage.py JSON report."
    )
    parser.add_argument("report", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    payload = json.loads(args.report.read_text(encoding="utf-8"))
    percent = _coverage_percent(payload)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(_render_badge(percent), encoding="utf-8", newline="\n")
    return 0


def _coverage_percent(payload: Any) -> int:
    if not isinstance(payload, dict) or not isinstance(payload.get("totals"), dict):
        raise ValueError("coverage report does not contain totals")

    totals = payload["totals"]
    display = totals.get("percent_covered_display")
    if isinstance(display, str):
        percent = int(display.rstrip("%"))
    else:
        percent = round(float(totals["percent_covered"]))
    return max(0, min(100, percent))


def _render_badge(percent: int) -> str:
    color = "#4c1" if percent >= 90 else "#97ca00" if percent >= 80 else "#dfb317"
    value = f"{percent}%"
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="108" height="20"
  role="img" aria-label="coverage: {value}">
  <title>coverage: {value}</title>
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r"><rect width="108" height="20" rx="3" fill="#fff"/></clipPath>
  <g clip-path="url(#r)">
    <rect width="67" height="20" fill="#555"/>
    <rect x="67" width="41" height="20" fill="{color}"/>
    <rect width="108" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle"
    font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">
    <text x="34.5" y="15" fill="#010101" fill-opacity=".3">coverage</text>
    <text x="34.5" y="14">coverage</text>
    <text x="86.5" y="15" fill="#010101" fill-opacity=".3">{value}</text>
    <text x="86.5" y="14">{value}</text>
  </g>
</svg>
"""


if __name__ == "__main__":
    raise SystemExit(main())
