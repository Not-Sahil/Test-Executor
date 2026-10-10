import os
import subprocess
import re

CURL = "curl.exe" if os.name == "nt" else "curl"


def _result(status, summary, details=None, evidence=None):
    return {
        "status": status,
        "summary": summary,
        "details": details or {},
        "evidence": evidence or [],
    }


def curl_request(url, host=None):

    command = [
        CURL,
        "-L",
        "--max-time", "15",
        "-sS",
        "-D", "-",
        url
    ]

    if host:
        command.extend([
            "-H",
            f"Host: {host}"
        ])

    try:

        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

        if result.returncode != 0:
            return None

        return result.stdout.decode(
            "utf-8",
            errors="replace"
        )

    except FileNotFoundError:

        print("\nERROR: CURL was not found.")
        return None


def extract_status(response):

    matches = re.findall(
        r"HTTP/\d(?:\.\d)?\s+(\d{3})",
        response
    )

    if matches:
        return matches[-1]

    return None


def extract_location(response):

    matches = re.findall(
        r"^Location:\s*(.+)$",
        response,
        re.IGNORECASE | re.MULTILINE
    )

    if matches:
        return matches[-1].strip()

    return None


def scan_host_header(url):

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = re.search(
        r"https?://([^/:]+)",
        url
    )

    if not parsed:
        print("Invalid URL.")
        return _result(
            "INCOMPLETE",
            "The scanner did not complete because the target URL was invalid.",
            {"error": "invalid_url", "target": url},
        )

    original_host = parsed.group(1)

    # Reserved testing hostname
    test_host = "test.invalid"

    print("\n" + "=" * 70)
    print("             HOST HEADER SECURITY SCANNER")
    print("=" * 70)

    print("Target       :", url)
    print("Normal Host  :", original_host)
    print("Test Host    :", test_host)
    print("-" * 70)

    # --------------------------------------------------------
    # NORMAL REQUEST
    # --------------------------------------------------------

    print("\n[1] Sending normal request...")

    normal_response = curl_request(url)

    if not normal_response:

        print("\nCONNECTION ERROR")
        print("Normal request failed.")
        return _result(
            "INCOMPLETE",
            "The scanner did not complete because the target request failed. "
            "This is not a SAFE or UNSAFE security finding.",
            {"error": "connection_error", "stage": "normal_request"},
        )

    normal_status = extract_status(normal_response)
    normal_location = extract_location(normal_response)

    print("    Status   :", normal_status)

    if normal_location:
        print("    Location :", normal_location)
    else:
        print("    Location : Not present")

    # --------------------------------------------------------
    # HOST HEADER TEST
    # --------------------------------------------------------

    print("\n[2] Sending controlled Host header...")

    injected_response = curl_request(
        url,
        host=test_host
    )

    if not injected_response:

        print("\nCONNECTION ERROR")
        print("Host-header test failed.")
        return _result(
            "INCOMPLETE",
            "The scanner did not complete because the Host-header test request failed. "
            "This is not a SAFE or UNSAFE security finding.",
            {"error": "connection_error", "stage": "host_header_test"},
        )

    injected_status = extract_status(
        injected_response
    )

    injected_location = extract_location(
        injected_response
    )

    print("    Status   :", injected_status)

    if injected_location:
        print("    Location :", injected_location)
    else:
        print("    Location : Not present")

    # --------------------------------------------------------
    # CHECK REFLECTION
    # --------------------------------------------------------

    response_lower = injected_response.lower()

    host_reflected = test_host.lower() in response_lower

    location_reflected = (
        injected_location
        and test_host.lower() in injected_location.lower()
    )

    # --------------------------------------------------------
    # FINAL RESULT
    # --------------------------------------------------------

    print("\n" + "=" * 70)

    details = {
        "original_host": original_host,
        "test_host": test_host,
        "normal_status": normal_status,
        "injected_status": injected_status,
        "normal_location": normal_location,
        "injected_location": injected_location,
        "host_reflected": host_reflected,
        "location_reflected": location_reflected,
    }

    if location_reflected:

        print("OVERALL STATUS : POTENTIALLY UNSAFE")

        print("\nSECURITY ISSUE DETECTED")
        print("-" * 70)

        print(
            "The application appears to use the supplied Host "
            "value when generating a redirect."
        )

        print("\nEvidence:")
        print(
            "  Test Host :",
            test_host
        )

        print(
            "  Location  :",
            injected_location
        )

        print("\nWHY THIS MATTERS:")

        print(
            "An application that trusts an unvalidated Host value "
            "when generating URLs or redirects may expose security "
            "risks such as malicious redirects or unsafe URL generation."
        )

        print("\nRECOMMENDED ACTION:")

        print(
            "Validate incoming hostnames against an approved list "
            "and avoid using untrusted Host values for security-sensitive "
            "URL generation."
        )

        print("\n" + "=" * 70)
        return _result(
            "UNSAFE",
            "The supplied test Host value influenced a redirect.",
            details,
            [f"Location: {injected_location}"],
        )

    if host_reflected:

        print("OVERALL STATUS : REVIEW REQUIRED")

        print("\nPOSSIBLE HOST HEADER REFLECTION")
        print("-" * 70)

        print(
            f"The test hostname '{test_host}' was found in "
            "the server response."
        )

        print(
            "\nThis does not by itself confirm a vulnerability."
        )

        print(
            "Manual validation is required to determine whether "
            "the reflected value is used in a security-sensitive context."
        )

        print("\n" + "=" * 70)
        return _result(
            "REVIEW REQUIRED",
            "The test Host value was reflected; manual validation is recommended.",
            details,
            [f"Test host {test_host} was reflected in the response."],
        )

    print("OVERALL STATUS : SAFE")

    print("\nSECURITY ISSUE DETECTED")
    print("-" * 70)

    print("No Host header injection indicator was detected.")

    print(
        "\nThe supplied test hostname was not reflected "
        "in the examined response."
    )

    print("\n" + "=" * 70)
    return _result(
        "SAFE",
        "No Host-header injection indicator was identified.",
        details,
    )


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    print("\nHost Header Injection Scanner")
    print("-----------------------------")

    url = input("Enter target URL: ").strip()

    if not url:

        print("\nERROR: URL cannot be empty.")

    else:

        scan_host_header(url)