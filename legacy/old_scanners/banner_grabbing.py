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


def scan_banner(url):

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    print("\n" + "=" * 65)
    print("           BANNER DISCLOSURE SECURITY SCANNER")
    print("=" * 65)
    print("Target:", url)
    print("-" * 65)

    try:
        # Run CURL
        result = subprocess.run(
            [
                CURL,
                "-I",
                "-L",
                "--max-time", "10",
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

        # ------------------------------------------------
        # Extract HTTP status
        # ------------------------------------------------

        status_matches = re.findall(
            r"HTTP/\d(?:\.\d)?\s+(\d{3})",
            curl_output
        )

        status_code = status_matches[-1] if status_matches else "Unknown"

        # ------------------------------------------------
        # Extract headers
        # ------------------------------------------------

        headers_to_check = [
            "Server",
            "X-Powered-By",
            "X-AspNet-Version",
            "X-AspNetMvc-Version"
        ]

        findings = []

        for header in headers_to_check:

            matches = re.findall(
                rf"^{re.escape(header)}:\s*(.+)$",
                curl_output,
                re.IGNORECASE | re.MULTILINE
            )

            for value in matches:

                # Detect version numbers such as:
                # Apache/2.4.49
                # nginx/1.18.0
                # PHP/8.2.10
                # ASP.NET/4.0.30319

                version_match = re.search(
                    r"([A-Za-z][A-Za-z0-9._-]*)\s*[/ ]\s*(\d+(?:\.\d+)+)",
                    value
                )

                if version_match:

                    findings.append({
                        "header": header,
                        "value": value.strip(),
                        "version": version_match.group(0)
                    })

        # ------------------------------------------------
        # Extract useful CURL information
        # ------------------------------------------------

        server_header = re.findall(
            r"^Server:\s*(.+)$",
            curl_output,
            re.IGNORECASE | re.MULTILINE
        )

        powered_by = re.findall(
            r"^X-Powered-By:\s*(.+)$",
            curl_output,
            re.IGNORECASE | re.MULTILINE
        )

        content_type = re.findall(
            r"^Content-Type:\s*(.+)$",
            curl_output,
            re.IGNORECASE | re.MULTILINE
        )

        location = re.findall(
            r"^Location:\s*(.+)$",
            curl_output,
            re.IGNORECASE | re.MULTILINE
        )

        # ------------------------------------------------
        # Display CURL evidence
        # ------------------------------------------------

        print("\nCURL RESPONSE DETAILS")
        print("-" * 65)

        print("HTTP Status :", status_code)

        if server_header:
            print("Server      :", server_header[-1])
        else:
            print("Server      : Not disclosed")

        if powered_by:
            print("Powered By  :", powered_by[-1])
        else:
            print("Powered By  : Not disclosed")

        if content_type:
            print("Content-Type:", content_type[-1])
        else:
            print("Content-Type: Not disclosed")

        if location:
            print("Redirect    :", location[-1])

        # ------------------------------------------------
        # Security result
        # ------------------------------------------------

        print("\n" + "-" * 65)

        if findings:

            print("STATUS : UNSAFE")
            print("REASON : Server/software version disclosure detected.")

            print("\nBANNER DISCLOSURE EVIDENCE:")

            for finding in findings:

                print("\n  Header  :", finding["header"])
                print("  Value   :", finding["value"])
                print("  Version :", finding["version"])

            print("\nWHY UNSAFE?")
            print(
                "The HTTP response exposes software/version information "
                "that can assist technology fingerprinting and vulnerability research."
            )

            print("\n" + "=" * 65)
            return _result(
                "UNSAFE",
                "Software/server version information was disclosed in HTTP response headers.",
                {
                    "http_status": status_code,
                    "findings": findings,
                },
                [f"{item['header']}: {item['value']}" for item in findings],
            )

        print("STATUS : SAFE")
        print(
            "REASON : No server/software version was detected "
            "in the checked HTTP response headers."
        )

        print("\nWHY SAFE?")
        print(
            "CURL did not identify a software version in the "
            "Server, X-Powered-By, or ASP.NET version headers."
        )

        print("\n" + "=" * 65)
        return _result(
            "SAFE",
            "No software version disclosure was identified by the banner scanner.",
            {
                "http_status": status_code,
                "server": server_header[-1] if server_header else None,
                "x_powered_by": powered_by[-1] if powered_by else None,
            },
        )

    except FileNotFoundError:
        print("\nERROR: CURL was not found.")
        print("Install CURL or make sure it is available in PATH.")
        return _result(
            "INCOMPLETE",
            "The scanner did not complete because CURL was not found on PATH.",
            {"error": "curl_not_found"},
        )

    except Exception as e:
        print("\nERROR:", e)
        return _result(
            "ERROR",
            f"Scanner error: {e}",
            {"error": str(e)},
        )


# ========================================================
# MAIN
# ========================================================

if __name__ == "__main__":
    print("\nBanner Disclosure Scanner")
    print("-------------------------")

    url = input("Enter target URL: ").strip()

    if not url:
        print("ERROR: URL cannot be empty.")
    else:
        scan_banner(url)