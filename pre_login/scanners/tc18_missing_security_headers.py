import os
import subprocess
import re

CURL = "curl.exe" if os.name == "nt" else "curl"


# ============================================================
# IDEAL / RECOMMENDED VALUES
# ============================================================

IDEAL_HEADERS = {
    "Content-Security-Policy":
        "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",

    "Strict-Transport-Security":
        "max-age=63072000; includeSubDomains; preload",

    "X-Content-Type-Options":
        "nosniff",

    "X-Frame-Options":
        "DENY",

    "Referrer-Policy":
        "strict-origin-when-cross-origin"
}


def normalize(value):
    """
    Normalize header values for comparison.
    """
    return " ".join(value.lower().split())


def _result(status, summary, details=None, evidence=None):
    return {
        "status": status,
        "summary": summary,
        "details": details or {},
        "evidence": evidence or [],
    }


def check_csp(value):
    """Evaluate CSP so hardening gaps are not confused with confirmed vulnerabilities."""
    value_lower = value.lower()
    hardening_directives = ["default-src", "object-src", "base-uri"]
    return {
        "frame_ancestors_present": "frame-ancestors" in value_lower,
        "missing_hardening": [
            directive
            for directive in hardening_directives
            if directive not in value_lower
        ],
    }

def check_hsts(value):
    """Evaluate HSTS without treating optional hardening attributes as vulnerabilities."""
    value_lower = value.lower()
    max_age = re.search(r"max-age\s*=\s*(\d+)", value_lower)

    if not max_age:
        return {
            "status": "UNSAFE",
            "reason": "max-age missing",
            "max_age": None,
            "hardening": [],
        }

    max_age_value = int(max_age.group(1))

    if max_age_value < 31536000:
        return {
            "status": "REVIEW REQUIRED",
            "reason": "max-age is less than 31536000 (1 year)",
            "max_age": max_age_value,
            "hardening": [],
        }

    hardening = []
    if max_age_value < 63072000:
        hardening.append("max-age is below the 2-year recommended hardening target")
    if "includesubdomains" not in value_lower:
        hardening.append("includeSubDomains not present")
    if "preload" not in value_lower:
        hardening.append("preload not present")

    return {
        "status": "REVIEW REQUIRED" if hardening else "SAFE",
        "reason": "; ".join(hardening) if hardening else "HSTS configuration provides the configured baseline",
        "max_age": max_age_value,
        "hardening": hardening,
    }

def scan_security_headers(url, verify_tls=True):

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    print("\n" + "=" * 75)
    print("             SECURITY HEADER VULNERABILITY SCANNER")
    print("=" * 75)

    print("Target:", url)
    print("-" * 75)

    # ========================================================
    # CURL COMMAND
    # ========================================================

    try:

        curl_cmd = [
            CURL,
            "-I",
            "-L",
            "--max-time", "15",
            "-sS",
        ]
        if not verify_tls:
            curl_cmd.append("--insecure")
        curl_cmd.append(url)

        result = subprocess.run(
            curl_cmd,
            capture_output=True,
            text=True
        )

        stderr = (result.stderr or "")
        if result.returncode != 0 and verify_tls and (
            "CERT" in stderr.upper()
            or "SSL" in stderr.upper()
            or "SCHANNEL" in stderr.upper()
        ):
            return scan_security_headers(url, verify_tls=False)

        if result.returncode != 0:

            print("\nCONNECTION ERROR")
            print(result.stderr)
            return _result(
                "INCOMPLETE",
                "The scanner did not complete because the target request failed. "
                "This is not a SAFE or UNSAFE security finding.",
                {"error": "connection_error", "stderr": result.stderr},
            )

        curl_output = result.stdout

    except FileNotFoundError:
        try:
            from .common import request as http_request
            response = http_request(url, method="GET", verify_tls=verify_tls, allow_redirects=True)
            curl_output = "\n".join(
                f"{name}: {value}" for name, value in response.headers.items()
            )
        except Exception as exc:
            print("\nERROR: CURL was not found and HTTP fallback failed.")
            return _result(
                "INCOMPLETE",
                "The scanner did not complete because CURL was not found on PATH.",
                {"error": "curl_not_found", "fallback_error": str(exc)},
            )

    # ========================================================
    # EXTRACT HEADERS
    # ========================================================

    headers = {}

    for header_name in IDEAL_HEADERS:

        matches = re.findall(
            rf"^[ \t]*{re.escape(header_name)}:[ \t]*([^\r\n]*)$",
            curl_output,
            re.IGNORECASE | re.MULTILINE
        )

        if matches:
            headers[header_name] = matches[-1].strip()
        else:
            headers[header_name] = None

    # ========================================================
    # CHECK EACH HEADER
    # ========================================================

    results = {}

    # --------------------------------------------------------
    # 1. CONTENT-SECURITY-POLICY
    # --------------------------------------------------------

    csp = headers["Content-Security-Policy"]

    if not csp:
        results["Content-Security-Policy"] = {
            "status": "UNSAFE",
            "reason": "Header missing",
        }
    else:
        csp_analysis = check_csp(csp)
        if not csp_analysis["frame_ancestors_present"]:
            results["Content-Security-Policy"] = {
                "status": "REVIEW REQUIRED",
                "reason": "frame-ancestors is missing; clickjacking protection should be verified by the dedicated clickjacking testcase.",
                "missing_hardening_directives": csp_analysis["missing_hardening"],
            }
        elif csp_analysis["missing_hardening"]:
            results["Content-Security-Policy"] = {
                "status": "REVIEW REQUIRED",
                "reason": "Recommended CSP hardening directives missing: " + ", ".join(csp_analysis["missing_hardening"]),
                "missing_hardening_directives": csp_analysis["missing_hardening"],
            }
        else:
            results["Content-Security-Policy"] = {
                "status": "SAFE",
                "reason": "CSP contains the configured protection and hardening directives",
            }


    # --------------------------------------------------------

    hsts = headers["Strict-Transport-Security"]

    if not hsts:
        results["Strict-Transport-Security"] = {
            "status": "UNSAFE",
            "reason": "Header missing",
        }
    else:
        results["Strict-Transport-Security"] = check_hsts(hsts)


    # --------------------------------------------------------

    x_content = headers["X-Content-Type-Options"]

    if not x_content:

        results["X-Content-Type-Options"] = {
            "status": "UNSAFE",
            "reason": "Header missing"
        }

    elif normalize(x_content) == "nosniff":

        results["X-Content-Type-Options"] = {
            "status": "SAFE",
            "reason": "Correct value: nosniff"
        }

    else:

        results["X-Content-Type-Options"] = {
            "status": "UNSAFE",
            "reason": "Expected value: nosniff"
        }

    # --------------------------------------------------------
    # 4. X-FRAME-OPTIONS
    # --------------------------------------------------------

    x_frame = headers["X-Frame-Options"]

    if not x_frame:

        results["X-Frame-Options"] = {
            "status": "UNSAFE",
            "reason": "Header missing"
        }

    elif normalize(x_frame) == "deny":

        results["X-Frame-Options"] = {
            "status": "SAFE",
            "reason": "Correct value: DENY"
        }

    else:

        results["X-Frame-Options"] = {
            "status": "UNSAFE",
            "reason": "Expected baseline value: DENY"
        }

    # --------------------------------------------------------
    # 5. REFERRER-POLICY
    # --------------------------------------------------------

    referrer = headers["Referrer-Policy"]

    safe_referrer_policies = {
        "no-referrer",
        "no-referrer-when-downgrade",
        "origin",
        "origin-when-cross-origin",
        "same-origin",
        "strict-origin",
        "strict-origin-when-cross-origin",
    }

    if not referrer:
        results["Referrer-Policy"] = {
            "status": "REVIEW REQUIRED",
            "reason": "Header missing; an explicit referrer policy is recommended",
        }
    elif normalize(referrer) in safe_referrer_policies:
        results["Referrer-Policy"] = {
            "status": "SAFE",
            "reason": "A recognized restrictive/referrer-reducing policy is present",
        }
    else:
        results["Referrer-Policy"] = {
            "status": "REVIEW REQUIRED",
            "reason": "Configured value is not in the scanner's recognized safe policy set",
        }

    # ========================================================
    # DISPLAY CURL INFORMATION
    # ========================================================

    print("\nCURL SECURITY HEADER RESULTS")
    print("-" * 75)

    for header_name in IDEAL_HEADERS:

        value = headers[header_name]

        print("\n" + header_name)

        if value:
            print("  Found :", value)
        else:
            print("  Found : NOT PRESENT")

        print("  Ideal :", IDEAL_HEADERS[header_name])

        print(
            "  Status:",
            results[header_name]["status"]
        )

        print(
            "  Reason:",
            results[header_name]["reason"]
        )

    # ========================================================
    # OVERALL RESULT
    # ========================================================

        # ========================================================
    # OVERALL RESULT - CLIENT FRIENDLY
    # ========================================================

    unsafe_headers = [
        header
        for header in results
        if results[header]["status"] == "UNSAFE"
    ]

    review_headers = [
        header
        for header in results
        if results[header]["status"] == "REVIEW REQUIRED"
    ]

    print("\n" + "=" * 75)

    if unsafe_headers:

        print("OVERALL STATUS : UNSAFE")

        print("\nSECURITY ISSUES DETECTED")
        print("-" * 75)

        # Client-friendly explanations
        client_messages = {
            "Content-Security-Policy":
                "Protection against malicious scripts and unauthorized "
                "content is incomplete.",

            "Strict-Transport-Security":
                "Protection against insecure connections is incomplete.",

            "X-Content-Type-Options":
                "Protection against incorrect interpretation of "
                "website content is incomplete.",

            "X-Frame-Options":
                "Protection against unauthorized page embedding "
                "is incomplete.",

            "Referrer-Policy":
                "Protection of browsing and referral information "
                "is incomplete."
        }

        for header in unsafe_headers:

            actual_value = headers[header]

            if actual_value:
                status = "NEEDS IMPROVEMENT"
            else:
                status = "MISSING"

            print(f"\n[{header}]")
            print(f"  Status : {status}")
            print(f"  Issue  : {client_messages[header]}")

        print("\n" + "-" * 75)

        print(
            f"{len(unsafe_headers)} security protection(s) "
            "require attention."
        )

        print(
            "\nRECOMMENDED ACTION"
        )

        print(
            "Review and strengthen the identified security "
            "protections according to the website's requirements."
        )

        print("\n" + "=" * 75)
        return _result(
            "UNSAFE",
            "One or more configured security-header protections are missing or below the baseline.",
            {
                "headers": headers,
                "checks": results,
                "unsafe_headers": unsafe_headers,
                "review_headers": review_headers,
                "critical_finding_confirmed": True,
            },
            [
                f"{header}: {results[header]['reason']}"
                for header in unsafe_headers
            ],
        )

    if review_headers:
        print("OVERALL STATUS : REVIEW REQUIRED")
        print("\nSECURITY HARDENING ITEMS")
        print("-" * 75)

        for header in review_headers:
            print(f"\n[{header}]")
            print("  Status : REVIEW REQUIRED")
            print(f"  Reason : {results[header]['reason']}")

        print("\n" + "=" * 75)
        return _result(
            "REVIEW REQUIRED",
            "No critical security-header absence was confirmed, but one or more header configurations require hardening or manual policy review.",
            {
                "headers": headers,
                "checks": results,
                "unsafe_headers": unsafe_headers,
                "review_headers": review_headers,
                "critical_finding_confirmed": False,
            },
            [
                f"{header}: {results[header]['reason']}"
                for header in review_headers
            ],
        )

    print("OVERALL STATUS : SAFE")

    print("\nSECURITY ISSUES DETECTED")
    print("-" * 75)

    print("None")

    print(
        "\nAll 5 security protections are present and "
        "meet the configured security baseline."
    )

    print("\n" + "=" * 75)
    return _result(
        "SAFE",
        "The five configured security-header checks met the scanner baseline.",
        {
            "headers": headers,
            "checks": results,
        },
    )


# ============================================================
# MAIN PROGRAM
# ============================================================

if __name__ == "__main__":
    print("\nSecurity Header Vulnerability Scanner")
    print("------------------------------------")

    url = input("Enter target URL: ").strip()

    if not url:

        print("\nERROR: URL cannot be empty.")

    else:

        scan_security_headers(url)