import re
from urllib.parse import urljoin

import requests


REQUEST_TIMEOUT = 10
USER_AGENT = "SecurityAssessmentScanner/1.0"


def _result(status, summary, details=None, evidence=None):
    return {
        "status": status,
        "summary": summary,
        "details": details or {},
        "evidence": evidence or [],
    }


def _normalise_url(url):
    url = (url or "").strip()
    if not url:
        raise ValueError("Target URL cannot be empty.")
    if not url.lower().startswith(("http://", "https://")):
        url = "https://" + url
    return url


def _extract_version(value):
    """Return a dotted numeric software version when one is present."""
    match = re.search(r"\b(?:v)?(\d+(?:\.\d+)+)\b", value or "")
    return match.group(1) if match else None


def _extract_technology_name(value):
    """Best-effort technology/server name extraction for reporting."""
    value = (value or "").strip()
    if not value:
        return None

    # Common banner format: nginx/1.24.0, Apache/2.4.62, PHP/8.3.1
    name = re.split(r"[/ ]", value, maxsplit=1)[0].strip()
    return name or value


def _collect_disclosures(response):
    """Collect banner disclosures from every response in a redirect chain.

    This deliberately reads parsed HTTP headers from requests rather than
    parsing curl's raw text output. That prevents a blank `Server:` header
    from accidentally consuming the following `Date:` line.
    """
    responses = list(getattr(response, "history", [])) + [response]

    headers_to_check = (
        "Server",
        "X-Powered-By",
        "X-AspNet-Version",
        "X-AspNetMvc-Version",
    )

    findings = []
    seen = set()

    for item in responses:
        response_url = str(getattr(item, "url", ""))
        response_status = int(getattr(item, "status_code", 0) or 0)

        for header_name in headers_to_check:
            value = item.headers.get(header_name)

            # Critical: an empty/missing header is NOT a disclosure and must
            # never consume or inherit the next HTTP header.
            if value is None:
                continue

            value = str(value).strip()
            if not value:
                continue

            key = (
                response_status,
                response_url,
                header_name.lower(),
                value.lower(),
            )
            if key in seen:
                continue
            seen.add(key)

            version = _extract_version(value)
            technology = _extract_technology_name(value)

            findings.append(
                {
                    "header": header_name,
                    "value": value,
                    "technology": technology,
                    "version": version,
                    "disclosure_type": (
                        "server/software name and version"
                        if version
                        else "server/software name only"
                    ),
                    "http_status": response_status,
                    "response_url": response_url,
                }
            )

    return findings


def scan_banner(url, verify_tls=True):
    url = _normalise_url(url)

    print("\n" + "=" * 65)
    print("           BANNER DISCLOSURE SECURITY SCANNER")
    print("=" * 65)
    print("Target:", url)
    print("-" * 65)

    session = requests.Session()
    session.headers.update({
        "User-Agent": USER_AGENT,
        "Accept": "*/*",
    })

    try:
        # Use a real GET request instead of parsing `curl -I` output.
        # Some applications/proxies treat HEAD differently from GET.
        try:
            response = session.get(
                url,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True,
                verify=verify_tls,
                stream=True,
            )
        except requests.exceptions.SSLError:
            if not verify_tls:
                raise
            response = session.get(
                url,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True,
                verify=False,
                stream=True,
            )

        findings = _collect_disclosures(response)

        final_headers = response.headers
        final_server = final_headers.get("Server")
        final_powered_by = final_headers.get("X-Powered-By")
        final_aspnet = final_headers.get("X-AspNet-Version")
        final_aspnet_mvc = final_headers.get("X-AspNetMvc-Version")
        content_type = final_headers.get("Content-Type")
        final_url = str(response.url)

        redirect_chain = [
            {
                "status": item.status_code,
                "url": str(item.url),
                "location": item.headers.get("Location"),
            }
            for item in response.history
        ]

        print("\nHTTP RESPONSE DETAILS")
        print("-" * 65)
        print("HTTP Status :", response.status_code)
        print("Final URL   :", final_url)

        if final_server:
            print("Server      :", final_server)
        else:
            print("Server      : Not disclosed")

        if final_powered_by:
            print("Powered By  :", final_powered_by)
        else:
            print("Powered By  : Not disclosed")

        if final_aspnet:
            print("ASP.NET Ver :", final_aspnet)
        else:
            print("ASP.NET Ver : Not disclosed")

        if final_aspnet_mvc:
            print("ASP.NET MVC :", final_aspnet_mvc)
        else:
            print("ASP.NET MVC : Not disclosed")

        if content_type:
            print("Content-Type:", content_type)
        else:
            print("Content-Type: Not disclosed")

        if redirect_chain:
            print("Redirects   :", len(redirect_chain))

        print("\n" + "-" * 65)

        if findings:
            version_disclosed = any(item["version"] for item in findings)

            print("STATUS : UNSAFE")
            print(
                "REASON : Server/software identification information "
                "was disclosed in HTTP response headers."
            )

            print("\nBANNER DISCLOSURE EVIDENCE:")

            for finding in findings:
                print("\n  Header      :", finding["header"])
                print("  Value       :", finding["value"])
                print("  Technology  :", finding["technology"] or "Not identified")
                print("  Version     :", finding["version"] or "Not disclosed")
                print("  HTTP Status :", finding["http_status"])
                print("  Response    :", finding["response_url"])

            print("\nWHY UNSAFE?")
            print(
                "The response exposes server or software identity information. "
                "A disclosed product name is sufficient for this testcase to be "
                "classified as UNSAFE; a disclosed version is recorded separately."
            )

            print("\n" + "=" * 65)

            return _result(
                "UNSAFE",
                "Server/software identification information was disclosed in HTTP response headers.",
                {
                    "http_status": response.status_code,
                    "final_url": final_url,
                    "findings": findings,
                    "banner_disclosed": True,
                    "version_disclosed": bool(version_disclosed),
                    "redirect_chain": redirect_chain,
                },
                [
                    f"{item['header']}: {item['value']}"
                    for item in findings
                ],
            )

        print("STATUS : SAFE")
        print(
            "REASON : No server/software identification information was "
            "detected in the checked HTTP response headers."
        )

        print("\nWHY SAFE?")
        print(
            "No non-empty Server, X-Powered-By, X-AspNet-Version, or "
            "X-AspNetMvc-Version header was observed in the response chain."
        )

        print("\n" + "=" * 65)

        return _result(
            "SAFE",
            "No server/software identification disclosure was identified by the banner scanner.",
            {
                "http_status": response.status_code,
                "final_url": final_url,
                "server": final_server,
                "x_powered_by": final_powered_by,
                "x_aspnet_version": final_aspnet,
                "x_aspnet_mvc_version": final_aspnet_mvc,
                "banner_disclosed": False,
                "version_disclosed": False,
                "redirect_chain": redirect_chain,
            },
        )

    except requests.exceptions.SSLError as exc:
        print("\nTLS ERROR:", exc)
        return _result(
            "INCOMPLETE",
            "The scanner could not complete because TLS certificate verification failed.",
            {
                "error": "tls_verification_failed",
                "message": str(exc),
            },
        )

    except requests.exceptions.RequestException as exc:
        print("\nCONNECTION ERROR:", exc)
        return _result(
            "INCOMPLETE",
            "The scanner did not complete because the target request failed. "
            "This is not a SAFE or UNSAFE security finding.",
            {
                "error": "connection_error",
                "message": str(exc),
            },
        )

    except Exception as exc:
        print("\nERROR:", exc)
        return _result(
            "ERROR",
            f"Scanner error: {exc}",
            {
                "error": str(exc),
            },
        )


if __name__ == "__main__":
    print("\nBanner Disclosure Scanner")
    print("-------------------------")
    target = input("Enter target URL: ").strip()

    if not target:
        print("ERROR: URL cannot be empty.")
    else:
        scan_banner(target)
