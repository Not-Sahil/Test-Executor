"""TC25 - Time-Based SQL Injection Scanner.

Determines whether controlled input produces reproducible, SQL-dependent response
delays, distinguishing genuine delays from network jitter and normal server load.
"""
from __future__ import annotations

import time
from typing import Any
import requests

from core.http_client import effective_verify_tls
from core.sqli_engine import (
    STATUS_ERROR,
    STATUS_INCOMPLETE,
    STATUS_REVIEW,
    STATUS_SAFE,
    STATUS_UNSAFE,
    discover_targets,
    execute_probe,
)
from payloads.manager import load_json_records, is_exhaustive_mode


def _load_time_probes(limit: int = 6) -> list[dict[str, Any]]:
    return load_json_records(
        "payloads_all_the_things/sql_injection/time_delay_probes.json",
        limit=limit if not is_exhaustive_mode() else None,
    )


def scan_time_based_sql_injection(
    url: str,
    *,
    verify_tls: bool = True,
    timeout: float = 10.0,
    max_targets: int = 3,
) -> dict[str, Any]:
    """Execute bounded Time-Based SQL injection assessment."""
    target_url = url.strip()
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url

    verify_tls, _ = effective_verify_tls(target_url, verify_tls)
    session = requests.Session()

    # 1. Measure baseline latency over 2 control requests
    baseline_latencies: list[float] = []
    try:
        for _ in range(2):
            t0 = time.perf_counter()
            resp = session.get(target_url, timeout=timeout, verify=verify_tls, allow_redirects=True)
            baseline_latencies.append(time.perf_counter() - t0)
    except Exception as exc:
        return {
            "status": STATUS_INCOMPLETE,
            "summary": f"Could not establish baseline timing measurements against {target_url}: {exc}",
            "evidence": [f"Connection error: {exc}"],
            "details": {"url": target_url, "error": str(exc)},
        }

    avg_baseline = sum(baseline_latencies) / len(baseline_latencies)
    targets = discover_targets(target_url, resp)[:max_targets]

    if not targets:
        return {
            "status": STATUS_SAFE,
            "summary": "No injectable query or form parameters were discovered on the target.",
            "evidence": [],
            "details": {"url": target_url, "avg_baseline_seconds": round(avg_baseline, 3)},
        }

    probes = _load_time_probes()
    evidence: list[str] = []
    time_sqli_confirmed = False
    ambiguous_timing = False
    confirmed_observations: list[dict[str, Any]] = []
    executed_count = 0
    timeouts_encountered = 0

    for target in targets:
        for probe in probes:
            expected_delay = float(probe.get("delay_seconds", 2))
            executed_count += 1

            # First timing probe observation
            _, elapsed1, err1 = execute_probe(session, target, probe["value"], timeout=timeout, verify=verify_tls)
            if err1 and "timed out" in err1.lower():
                timeouts_encountered += 1
                ambiguous_timing = True
                continue
            if err1 or elapsed1 is None:
                continue

            # Check if delay significantly exceeds baseline
            delay_threshold = avg_baseline + expected_delay - 0.4
            if elapsed1 >= delay_threshold:
                # Repeated confirmation observation to rule out network jitter
                _, elapsed2, err2 = execute_probe(session, target, probe["value"], timeout=timeout, verify=verify_tls)
                executed_count += 1
                if elapsed2 is not None and elapsed2 >= delay_threshold:
                    time_sqli_confirmed = True
                    confirmed_observations.append({
                        "parameter": target.name,
                        "probe": probe["name"],
                        "payload": probe["value"],
                        "expected_delay": expected_delay,
                        "observed_elapsed_1": round(elapsed1, 3),
                        "observed_elapsed_2": round(elapsed2, 3),
                        "avg_baseline_seconds": round(avg_baseline, 3),
                    })
                    evidence.append(
                        f"Parameter '{target.name}': Probe '{probe['name']}' produced reproducible SQL delay "
                        f"(Observation 1: {elapsed1:.2f}s, Observation 2: {elapsed2:.2f}s vs baseline {avg_baseline:.2f}s)."
                    )
                    break
                else:
                    ambiguous_timing = True
                    evidence.append(
                        f"Parameter '{target.name}': Transient delay ({elapsed1:.2f}s) was not reproducible on repeated test."
                    )

        if time_sqli_confirmed:
            break

    details = {
        "target": target_url,
        "avg_baseline_seconds": round(avg_baseline, 3),
        "probe_cap": len(probes) * 2,
        "executed_probe_count": executed_count,
        "timeouts_encountered": timeouts_encountered,
        "payloads_used": [
            {"name": p["name"], "payload": p["value"], "kind": "time_delay"}
            for p in probes[:max(executed_count, 2)]
        ],
        "confirmed_observations": confirmed_observations,
    }
    if confirmed_observations:
        details["triggering_payload"] = {
            "name": confirmed_observations[0]["probe"],
            "payload": confirmed_observations[0]["payload"],
            "parameter": confirmed_observations[0]["parameter"],
            "kind": "time_delay",
            "verdict": "UNSAFE",
        }

    if time_sqli_confirmed:
        return {
            "status": STATUS_UNSAFE,
            "summary": (
                f"Time-based SQL injection was confirmed on {target_url}: "
                f"controlled input produced reproducible, SQL-dependent execution delays."
            ),
            "evidence": evidence,
            "details": details,
        }

    if ambiguous_timing:
        return {
            "status": STATUS_REVIEW,
            "summary": (
                f"Suspicious timing delays or timeouts were observed on {target_url}, "
                f"but delays could not be conclusively confirmed as reproducible SQL execution."
            ),
            "evidence": evidence or [f"Encountered {timeouts_encountered} request timeout(s) during probe execution."],
            "details": details,
        }

    if executed_count == 0:
        return {
            "status": STATUS_INCOMPLETE,
            "summary": "Could not complete time-based SQL injection probes against target parameters.",
            "evidence": [],
            "details": details,
        }

    return {
        "status": STATUS_SAFE,
        "summary": "No time-based SQL injection delays were observed across tested parameters within configured bounds.",
        "evidence": [f"Tested {len(targets)} parameter(s) with {executed_count} time probe(s); responses remained consistent with baseline."],
        "details": details,
    }
