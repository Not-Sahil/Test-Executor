"""
run_default_creds_tests.py

Self-contained executor for WSTG-ATHN-02 (default credentials) test cases.
No dependency on the broader orchestrator/dispatch table yet — reads a
flat JSON list of test cases, runs each through default_creds_lane, and
writes a flat JSON list of results in the same result schema used
elsewhere in the pipeline.

Input test case schema (minimal, intentionally narrow to this lane):
[
  {
    "test_case_id": "TC-0134",          # optional; generated if absent
    "target": "http://demo.testfire.net", # base URL or host, no trailing slash needed
    "is_http": true,                      # true -> form/basic-auth checker, false -> Hydra
    "service_or_path": "/login.jsp",      # HTTP: login path. Non-HTTP: hydra service (e.g. "ssh")
    "product_hint": null,                 # optional filter into the wordlist (e.g. "mysql")
    "user_field": "uid",                   # optional; omitted -> parsed from the login HTML
    "pass_field": "passw",                 # optional; omitted -> parsed from the login HTML
    "max_attempts": null,                    # optional; omit or null = try the full wordlist
    "enabled": true                          # optional; false -> omit from the run. Hydra
                                             # cases stay dormant unless --enable-hydra
  }
]

If your existing build_test_cases.py schema differs, the mapping happens
in `_to_lane_args()` below — that's the one place to edit when this gets
wired into the real dispatcher later.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .default_credentials_engine import (
    CredPair,
    execute_default_creds_test,
    load_cred_pairs,
    HttpDefaultCredChecker,
    run_hydra_default_creds,
    LockoutGuard,
    ResultStatus,
)


def _filter_creds_by_product(creds: list[CredPair], product_hint: str | None) -> list[CredPair]:
    """If a test case names a product_hint (e.g. 'mysql'), narrow the
    wordlist to matching entries + generic entries, instead of firing the
    full list at a target we already know the product for. Deterministic
    filter, no LLM involved.
    """
    if not product_hint:
        return creds
    narrowed = [c for c in creds if c.product_hint in (product_hint, "generic")]
    return narrowed or creds  # fall back to full list if nothing matched


def _to_lane_args(test_case: dict) -> dict:
    """Single mapping point between the test-case schema and the lane's
    function signature. Edit here, not in the loop below, when the real
    executor's schema is finalized.
    """
    return {
        "test_case_id": test_case.get("test_case_id"),
        "target": test_case["target"],
        "is_http": bool(test_case.get("is_http", True)),
        "service_or_path": test_case.get("service_or_path", "/login"),
        "product_hint": test_case.get("product_hint"),
        "user_field": test_case.get("user_field"),  # None -> auto-detect from the login form
        "pass_field": test_case.get("pass_field"),
        "max_attempts": test_case.get("max_attempts"),
        "test_type": test_case.get("test_type", "default_creds"),
        "candidate_usernames": test_case.get("candidate_usernames"),
        "probe_password": test_case.get("probe_password"),
        "username": test_case.get("username"),
        "password": test_case.get("password"),
        "pairs": test_case.get("pairs"),
        "known_valid_username": test_case.get("known_valid_username"),
        "known_valid_password": test_case.get("known_valid_password"),
        "verify_tls": test_case.get("verify_tls", True),
    }


def run_one(test_case: dict, creds: list[CredPair], enable_hydra: bool = False) -> dict:
    args = _to_lane_args(test_case)
    scoped_creds = _filter_creds_by_product(creds, args["product_hint"])

    if args.get("test_type") == "enumeration":
        checker = HttpDefaultCredChecker(
            base_url=args["target"],
            verify_tls=bool(args.get("verify_tls", True)),
        )
        enum_kwargs: dict = {
            "known_valid_username": args.get("known_valid_username"),
        }
        if args.get("probe_password"):
            enum_kwargs["probe_password"] = args["probe_password"]
        result = checker.enumerate_usernames(
            login_path=args["service_or_path"],
            candidate_usernames=list(args.get("candidate_usernames") or []),
            **enum_kwargs,
        )
    elif args.get("test_type") in ("login_factors", "factor_diagnosis"):
        checker = HttpDefaultCredChecker(base_url=args["target"])
        pairs: list[tuple[str, str]] = []
        if args.get("username") is not None:
            pairs.append((str(args["username"]), str(args.get("password") or "")))
        for item in args.get("pairs") or []:
            if isinstance(item, dict):
                pairs.append((str(item.get("username", "")), str(item.get("password", ""))))
            elif isinstance(item, (list, tuple)) and len(item) >= 2:
                pairs.append((str(item[0]), str(item[1])))
        result = checker.diagnose_login_factor_pairs(
            login_path=args["service_or_path"],
            pairs=pairs,
            known_valid_username=args.get("known_valid_username"),
            known_valid_password=args.get("known_valid_password"),
        )
    elif args["is_http"]:
        checker = HttpDefaultCredChecker(
            base_url=args["target"],
            verify_tls=bool(args.get("verify_tls", True)),
        )
        max_attempts = args.get("max_attempts")
        guard = LockoutGuard(
            max_attempts=int(max_attempts) if max_attempts else None,
        )
        result = checker.run(
            login_path=args["service_or_path"],
            creds=scoped_creds,
            user_field=args["user_field"],
            pass_field=args["pass_field"],
            stop_on_first_hit=False,
            guard=guard,
        )
    else:
        result = run_hydra_default_creds(
            target=args["target"],
            service=args["service_or_path"],
            creds=scoped_creds,
            enable=enable_hydra,
        )

    if args["test_case_id"]:
        result.test_case_id = args["test_case_id"]

    out = json.loads(result.to_json())
    out["source_test_case"] = test_case
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="Run WSTG-ATHN-02 default-credential test cases")
    parser.add_argument("--input", required=True, help="JSON file: list of test cases")
    parser.add_argument("--creds", required=True, help="JSON file: default_creds_wordlist.json")
    parser.add_argument("--output", default="default_creds_results.json", help="Where to write results")
    parser.add_argument(
        "--max-attempts",
        type=int,
        default=None,
        help="Optional attempt cap. Default is no cap (full wordlist).",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS certificate verification for authorized test targets with invalid certificates.",
    )
    parser.add_argument(
        "--enable-hydra",
        action="store_true",
        help="Run non-HTTP (Hydra) test cases. They are omitted/dormant by default.",
    )
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"error: input file not found: {input_path}", file=sys.stderr)
        return 1

    test_cases = json.loads(input_path.read_text(encoding="utf-8"))
    if not isinstance(test_cases, list):
        print("error: input must be a JSON list of test cases", file=sys.stderr)
        return 1

    creds = load_cred_pairs(args.creds)

    results = []
    vulnerable_count = 0
    for tc in test_cases:
        if args.max_attempts is not None:
            tc = {**tc, "max_attempts": args.max_attempts}
        if args.insecure:
            tc = {**tc, "verify_tls": False}

        is_http = bool(tc.get("is_http", True))
        explicitly_disabled = tc.get("enabled", True) is False
        hydra_dormant = (not is_http) and (not args.enable_hydra)

        # Dormant/disabled cases stay out of the run entirely — no SKIPPED row.
        if hydra_dormant or explicitly_disabled:
            continue

        try:
            r = run_one(tc, creds, enable_hydra=args.enable_hydra)
        except Exception as e:  # noqa: BLE001 - surface as an ERROR result, don't crash the batch
            r = {
                "test_case_id": tc.get("test_case_id", "unknown"),
                "wstg_category": "WSTG-ATHN-02",
                "target": tc.get("target", "unknown"),
                "result": ResultStatus.ERROR.value,
                "evidence": [f"executor_exception:{e}"],
                "source_test_case": tc,
            }
        if r.get("result") == ResultStatus.SKIPPED.value:
            continue
        results.append(r)
        if r.get("result") == ResultStatus.VULNERABLE.value:
            vulnerable_count += 1
        print(f"[{r.get('result', '?').upper():16s}] {tc.get('target', '?')} "
              f"({r.get('test_case_id', '?')})")

    Path(args.output).write_text(json.dumps(results, indent=2), encoding="utf-8")

    print(f"\n{len(results)} test case(s) processed, {vulnerable_count} vulnerable finding(s).")
    print(f"Results written to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())