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
        "max-age=31536000; includeSubDomains; preload",

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
    """
    Check whether CSP exists and contains important
    baseline security directives.
    """

    value_lower = value.lower()

    required_directives = [
        "default-src",
        "object-src",
        "base-uri",
        "frame-ancestors"
    ]

    missing = []

    for directive in required_directives:
        if directive not in value_lower:
            missing.append(directive)

    return missing


def check_hsts(value):
    """
    Validate HSTS baseline configuration.
    """

    value_lower = value.lower()

    problems = []

    # Check max-age
    max_age = re.search(r"max-age\s*=\s*(\d+)", value_lower)

    if not max_age:
        problems.append("max-age missing")
    else:
        max_age_value = int(max_age.group(1))

        # 31536000 = 1 year
        if max_age_value < 31536000:
            problems.append("max-age is less than 31536000")

    # Check includeSubDomains
    if "includesubdomains" not in value_lower:
        problems.append("includeSubDomains missing")

    # Check preload
    if "preload" not in value_lower:
        problems.append("preload missing")

    return problems


def scan_security_headers(url):

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

        result = subprocess.run(
            [
                CURL,
                "-I",
                "-L",
                "--max-time", "15",
                "-sS",
                url
            ],
            capture_output=True,
            text=True
        )

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

        print("\nERROR: CURL was not found.")
        print("Make sure CURL is installed and available in PATH.")
        return _result(
            "INCOMPLETE",
            "The scanner did not complete because CURL was not found on PATH.",
            {"error": "curl_not_found"},
        )

    # ========================================================
    # EXTRACT HEADERS
    # ========================================================

    headers = {}

    for header_name in IDEAL_HEADERS:

        matches = re.findall(
            rf"^{re.escape(header_name)}:\s*(.+)$",
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
            "reason": "Header missing"
        }

    else:

        missing_directives = check_csp(csp)

        if missing_directives:

            results["Content-Security-Policy"] = {
                "status": "UNSAFE",
                "reason":
                    "Important CSP directives missing: "
                    + ", ".join(missing_directives)
            }

        else:

            results["Content-Security-Policy"] = {
                "status": "SAFE",
                "reason": "Required baseline directives present"
            }

    # --------------------------------------------------------
    # 2. HSTS
    # --------------------------------------------------------

    hsts = headers["Strict-Transport-Security"]

    if not hsts:

        results["Strict-Transport-Security"] = {
            "status": "UNSAFE",
            "reason": "Header missing"
        }

    else:

        hsts_problems = check_hsts(hsts)

        if hsts_problems:

            results["Strict-Transport-Security"] = {
                "status": "UNSAFE",
                "reason": "; ".join(hsts_problems)
            }

        else:

            results["Strict-Transport-Security"] = {
                "status": "SAFE",
                "reason": "HSTS configuration meets baseline"
            }

    # --------------------------------------------------------
    # 3. X-CONTENT-TYPE-OPTIONS
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

    if not referrer:

        results["Referrer-Policy"] = {
            "status": "UNSAFE",
            "reason": "Header missing"
        }

    elif normalize(referrer) == "strict-origin-when-cross-origin":

        results["Referrer-Policy"] = {
            "status": "SAFE",
            "reason":
                "Correct value: strict-origin-when-cross-origin"
        }

    else:

        results["Referrer-Policy"] = {
            "status": "UNSAFE",
            "reason":
                "Expected baseline value: "
                "strict-origin-when-cross-origin"
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
            },
            [
                f"{header}: {results[header]['reason']}"
                for header in unsafe_headers
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