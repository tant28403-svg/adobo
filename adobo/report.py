"""Write a run's results to disk as JSON and a self-contained HTML page.

The JSON is the record of what happened and is what other tools read. The HTML
exists because the point of the exercise is a comparison someone has to *read*:
which target survived, which mitigation moved which number. A score buried in a
JSON blob gets ignored; a page with the number at the top gets looked at.

Both writers are defensive on purpose. A reporting failure must never be the
reason a run's data is lost, so every problem degrades to a warning recorded on
the result rather than an exception.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from . import paths
from .models import RunResult

__all__ = ["WrittenReport", "write_json", "write_html", "write_reports"]


@dataclass(frozen=True, slots=True)
class WrittenReport:
    """Where a run's output landed."""

    json_path: Path | None = None
    html_path: Path | None = None
    warnings: tuple[str, ...] = ()


def _safe_name(run_id: str) -> str:
    """Make a run id safe to use as a filename.

    Run ids reach this function from config files and the wizard, so they cannot
    be trusted to be free of separators. A id of ``../../evil`` must not be able
    to write outside the reports directory.
    """
    cleaned = "".join(c if c.isalnum() or c in "-_." else "-" for c in run_id)
    cleaned = cleaned.strip(".-") or "run"
    return cleaned


def _ensure_dir(directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)


def write_json(result: RunResult, directory: Path | None = None) -> Path:
    """Write the machine-readable record. Raises on failure - the caller decides."""
    target_dir = directory or paths.results_dir()
    _ensure_dir(target_dir)
    path = target_dir / f"{_safe_name(result.run_id)}.json"
    payload = result.to_json_dict()
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    return path


def write_html(result: RunResult, directory: Path | None = None) -> Path:
    """Write the human-readable page."""
    target_dir = directory or paths.reports_dir()
    _ensure_dir(target_dir)
    path = target_dir / f"{_safe_name(result.run_id)}.html"
    path.write_text(render_html(result), encoding="utf-8")
    return path


def write_reports(result: RunResult, directory: Path | None = None) -> WrittenReport:
    """Write both artefacts, degrading to warnings rather than failing the run.

    A run that has already executed must not lose its data because, say, the
    reports directory is read-only. Losing the JSON is the serious failure; the
    HTML is a convenience, so each is attempted independently.
    """
    warnings: list[str] = []
    json_path: Path | None = None
    html_path: Path | None = None
    try:
        json_path = write_json(result, directory)
    except Exception as exc:
        warnings.append(f"could not write JSON result: {exc}")
    try:
        html_path = write_html(result, directory)
    except Exception as exc:
        warnings.append(f"could not write HTML report: {exc}")
    return WrittenReport(
        json_path=json_path, html_path=html_path, warnings=tuple(warnings)
    )


# --------------------------------------------------------------------------
# HTML
# --------------------------------------------------------------------------


def _fmt(value: Any, suffix: str = "") -> str:
    if value is None:
        return "-"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, float):
        return f"{value:,.2f}{suffix}"
    if isinstance(value, int):
        return f"{value:,}{suffix}"
    return f"{value}{suffix}"


def _escape(value: Any) -> str:
    text = str(value)
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _grade_class(grade: str) -> str:
    return {
        "A": "good", "B": "good", "C": "fair",
        "D": "poor", "F": "bad", "N/A": "unknown",
    }.get(grade.strip().upper(), "unknown")


def _sparkline(values: list[float], *, width: int = 240, height: int = 40) -> str:
    """A tiny inline SVG series.

    Deliberately not a chart library: the report has to open from a file:// URL
    with no network and no assets, which rules out anything that fetches itself.
    """
    points = [v for v in values if v is not None]
    if len(points) < 2:
        return '<p class="empty">not enough samples to plot</p>'
    low, high = min(points), max(points)
    span = (high - low) or 1.0
    step = width / (len(points) - 1)
    coords = " ".join(
        f"{round(i * step, 2)},{round(height - ((v - low) / span) * height, 2)}"
        for i, v in enumerate(points)
    )
    return (
        f'<svg class="spark" viewBox="0 0 {width} {height}" role="img" '
        f'preserveAspectRatio="none" aria-label="time series">'
        f'<polyline points="{coords}" fill="none" stroke="currentColor" '
        f'stroke-width="1.5" vector-effect="non-scaling-stroke"/></svg>'
    )


def _series_table(title: str, samples: list[Any], fields: list[tuple[str, str]]) -> str:
    if not samples:
        return f"<h3>{_escape(title)}</h3><p class='empty'>no samples recorded</p>"
    header = "".join(
        f"<th>{_escape(label)}</th>" for label, _ in [("t (s)", "")] + fields
    )
    rows = []
    for sample in samples:
        cells = f"<td>{_fmt(getattr(sample, 't', 0), 's')}</td>"
        for _, attr in fields:
            cells += f"<td>{_fmt(getattr(sample, attr, None))}</td>"
        rows.append(f"<tr>{cells}</tr>")
    return (
        f"<h3>{_escape(title)}</h3>"
        f"<table><thead><tr>{header}</tr></thead><tbody>{''.join(rows)}</tbody></table>"
    )


def probe_error_breakdown(probe: Any) -> str:
    """Which failures dominated.

    A run that scored badly because of timeouts is a different problem from one
    that scored badly because the target was refusing connections, and the
    headline number alone cannot tell you which one you have.
    """
    breakdown = getattr(probe, "error_breakdown", None) or {}
    if not breakdown:
        return ""
    rows = "".join(
        f"<tr><td>{_escape(reason)}</td><td>{_fmt(count)}</td></tr>"
        for reason, count in sorted(breakdown.items(), key=lambda kv: -kv[1])
    )
    return (
        "<h3>Why probes failed</h3>"
        f"<table><thead><tr><th>Reason</th><th>Count</th></tr></thead>"
        f"<tbody>{rows}</tbody></table>"
    )


def render_html(result: RunResult) -> str:
    """Render the full page. Pure, so it can be asserted on in tests."""
    score = result.score
    probe = result.probe
    attack = result.attack

    legend = "".join(
        f"<li><code>{_escape(d.value)}</code></li>" for d in result.defenses
    ) or "<li><em>none - baseline</em></li>"

    notes = "".join(f"<li>{_escape(note)}</li>" for note in result.notes) or (
        "<li><em>none</em></li>"
    )

    weights = "".join(
        f"<tr><td>{_escape(k)}</td><td>{_fmt(v)}</td></tr>"
        for k, v in sorted(score.weights.items())
    )

    pps_series: list[float] = []
    cpu_series = [s.cpu_percent for s in result.resource_samples]
    rss_series = [s.rss_mb for s in result.resource_samples]

    started: datetime = result.started_at
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>adobo run {_escape(result.run_id)}</title>
<style>
  :root {{
    --fg: #16181d; --muted: #5b6472; --line: #dfe3e9; --bg: #ffffff;
    --good: #1a7f4b; --fair: #9a6700; --poor: #bc4c00; --bad: #b42318;
    --unknown: #5b6472; --panel: #f7f8fa;
  }}
  @media (prefers-color-scheme: dark) {{
    :root {{
      --fg: #e6e9ef; --muted: #9aa4b2; --line: #2b303b; --bg: #14161a;
      --panel: #1c1f25; --good: #4ade80; --fair: #fbbf24;
      --poor: #fb923c; --bad: #f87171; --unknown: #9aa4b2;
    }}
  }}
  * {{ box-sizing: border-box; }}
  body {{
    font: 15px/1.55 ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
    color: var(--fg); background: var(--bg); margin: 0; padding: 2rem 1.25rem;
  }}
  main {{ max-width: 60rem; margin: 0 auto; }}
  h1 {{ font-size: 1.4rem; margin: 0 0 .25rem; }}
  h2 {{ font-size: 1.05rem; margin: 2rem 0 .5rem;
       text-transform: uppercase; letter-spacing: .06em; color: var(--muted); }}
  h3 {{ font-size: .95rem; margin: 1.25rem 0 .4rem; }}
  .sub {{ color: var(--muted); font-size: .875rem; margin: 0 0 1.5rem; }}
  .score {{ display: flex; align-items: baseline; gap: .75rem;
            padding: 1rem 1.25rem; background: var(--panel);
            border: 1px solid var(--line); border-radius: .5rem; }}
  .score .value {{ font-size: 2.75rem; font-weight: 650;
                   font-variant-numeric: tabular-nums; line-height: 1; }}
  .score .grade {{ font-size: 1.1rem; font-weight: 600; }}
  .good {{ color: var(--good); }} .fair {{ color: var(--fair); }}
  .poor {{ color: var(--poor); }} .bad {{ color: var(--bad); }}
  .unknown {{ color: var(--unknown); }}
  table {{ border-collapse: collapse; width: 100%; margin: .5rem 0 1rem;
           font-variant-numeric: tabular-nums; }}
  th, td {{ text-align: right; padding: .35rem .6rem;
            border-bottom: 1px solid var(--line); }}
  th:first-child, td:first-child {{ text-align: left; }}
  th {{ font-size: .78rem; text-transform: uppercase; letter-spacing: .04em;
        color: var(--muted); font-weight: 600; }}
  .grid {{ display: grid; gap: 1rem 2rem; grid-template-columns:
           repeat(auto-fit, minmax(15rem, 1fr)); }}
  .spark {{ width: 100%; height: 3rem; color: var(--muted); margin: .25rem 0; }}
  .empty {{ color: var(--muted); font-style: italic; }}
  code {{ font: .85em ui-monospace, "Cascadia Code", Consolas, monospace; }}
  ul {{ margin: .25rem 0; padding-left: 1.25rem; }}
  .pill {{ display: inline-block; padding: .1rem .5rem; border-radius: 1rem;
           background: var(--panel); border: 1px solid var(--line);
           font-size: .8rem; margin: 0 .25rem .25rem 0; }}
  footer {{ margin-top: 2.5rem; padding-top: 1rem; border-top: 1px solid var(--line);
            color: var(--muted); font-size: .8rem; }}
</style>
</head>
<body>
<main>
  <h1>adobo run {_escape(result.run_id)}</h1>
  <p class="sub">
    {_escape(result.label or 'unlabelled scenario')} &middot;
    started {_escape(started.isoformat())} &middot;
    {_fmt(result.duration_actual_s, 's')} actual
  </p>

  <h2>Resilience</h2>
  <div class="score">
    <span class="value">{_fmt(score.total)}</span>
    <span class="grade {_grade_class(score.grade)}">grade {_escape(score.grade)}</span>
  </div>
  <div class="grid" style="margin-top:1rem">
    <table>
      <tbody>
        <tr><td>Availability</td><td>{_fmt(score.availability, '%')}</td></tr>
        <tr><td>Latency score</td><td>{_fmt(score.latency, '%')}</td></tr>
        <tr><td>Error-free</td><td>{_fmt(score.error_rate, '%')}</td></tr>
        <tr><td>Resource headroom</td><td>{_fmt(score.headroom, '%')}</td></tr>
      </tbody>
    </table>
    <table>
      <thead><tr><th>Weight</th><th>Share</th></tr></thead>
      <tbody>{weights}</tbody>
    </table>
  </div>

  <h2>Attack</h2>
  <table>
    <tbody>
      <tr><td>Transport</td><td>{_escape(attack.transport.value)}</td></tr>
      <tr><td>Profile</td><td>{_escape(result.config.attack.profile.value)}</td></tr>
      <tr><td>Target</td><td>{_escape(result.config.target.host)}:{_escape(result.config.target.port)}</td></tr>
      <tr><td>Workers</td><td>{_fmt(result.config.attack.workers)}</td></tr>
      <tr><td>Packets attempted</td><td>{_fmt(attack.packets_attempted)}</td></tr>
      <tr><td>Packets sent</td><td>{_fmt(attack.packets_sent)}</td></tr>
      <tr><td>Bytes sent</td><td>{_fmt(attack.bytes_sent)}</td></tr>
      <tr><td>Send errors</td><td>{_fmt(attack.errors)}</td></tr>
      <tr><td>Requested pps</td><td>{_fmt(result.config.attack.pps)}</td></tr>
      <tr><td>Achieved pps</td><td>{_fmt(attack.achieved_pps)}</td></tr>
      <tr><td>Duration requested</td><td>{_fmt(result.config.attack.duration_seconds, 's')}</td></tr>
      <tr><td>Duration actual</td><td>{_fmt(attack.duration_actual_s, 's')}</td></tr>
    </tbody>
  </table>
  <h3>Throughput over time (sent pps)</h3>
  {_sparkline([s.sent_pps for s in result.counter_samples])}

  <h2>Availability probes</h2>
  <table>
    <tbody>
      <tr><td>Probes</td><td>{_fmt(probe.total)}</td></tr>
      <tr><td>Succeeded</td><td>{_fmt(probe.succeeded)}</td></tr>
      <tr><td>Failed</td><td>{_fmt(probe.failed)}</td></tr>
      <tr><td>Availability</td><td>{_fmt(probe.availability_pct, '%')}</td></tr>
      <tr><td>Mean latency</td><td>{_fmt(probe.latency.mean_ms, 'ms')}</td></tr>
      <tr><td>p50</td><td>{_fmt(probe.latency.p50_ms, 'ms')}</td></tr>
      <tr><td>p95</td><td>{_fmt(probe.latency.p95_ms, 'ms')}</td></tr>
      <tr><td>p99</td><td>{_fmt(probe.latency.p99_ms, 'ms')}</td></tr>
      <tr><td>Worst</td><td>{_fmt(probe.latency.max_ms, 'ms')}</td></tr>
    </tbody>
  </table>
  {probe_error_breakdown(probe)}

  <h2>Target resources</h2>
  <table>
    <tbody>
      <tr><td>Samples</td><td>{_fmt(result.target_stats.sample_count)}</td></tr>
      <tr><td>CPU mean</td><td>{_fmt(result.target_stats.cpu_percent_mean, '%')}</td></tr>
      <tr><td>CPU p95</td><td>{_fmt(result.target_stats.cpu_percent_p95, '%')}</td></tr>
      <tr><td>CPU max</td><td>{_fmt(result.target_stats.cpu_percent_max, '%')}</td></tr>
      <tr><td>RSS max</td><td>{_fmt(result.target_stats.rss_mb_max, 'MB')}</td></tr>
      <tr><td>Peak threads</td><td>{_fmt(result.target_stats.peak_threads)}</td></tr>
      <tr><td>Peak sockets</td><td>{_fmt(result.target_stats.peak_sockets)}</td></tr>
      <tr><td>Peak handles</td><td>{_fmt(result.target_stats.peak_handles)}</td></tr>
    </tbody>
  </table>
  <div class="grid">
    <div><h3>CPU %</h3>{_sparkline(cpu_series)}</div>
    <div><h3>RSS MB</h3>{_sparkline(rss_series)}</div>
  </div>

  <h2>Defenses in this run</h2>
  <p>{legend}</p>

  <h2>Notes</h2>
  <ul>{notes}</ul>

  <footer>
    Generated by adobo. Authorised lab use only - run this against a target you
    own or have written permission to test. No traffic was sent to any address
    you have not confirmed as yours.
  </footer>
</main>
</body>
</html>"""
