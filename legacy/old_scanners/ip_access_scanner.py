import os
import subprocess
import socket
import re
import hashlib
from urllib.parse import urlparse

CURL = "curl.exe" if os.name == "nt" else "curl"


def _result(status, summary, details=None, evidence=None):
    return {
        "status": status,
        "summary": summary,
        "details": details or {},
        "evidence": evidence or [],
    }


# ============================================================
# CURL REQUEST FUNCTION
# ============================================================

def curl_request(url, extra_args=None):

    command = [
        CURL,
        "-L",
        "--max-time", "15",
        "-sS",
        "-D", "-",
        url
    ]

    if extra_args:
        command[1:1] = extra_args

    try:

        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

        if result.returncode != 0:
            return None

        # Decode CURL output safely
        return result.stdout.decode(
            "utf-8",
            errors="replace"
        )

    except FileNotFoundError:

        print("\nERROR: CURL was not found.")
        print("Make sure CURL is installed and available in PATH.")
        return None

    except Exception as e:

        print("\nCURL ERROR:", e)
        return None


# ============================================================
# EXTRACT HTTP STATUS
# ============================================================

def get_status(response):

    if not response:
        return None

    matches = re.findall(
        r"HTTP/\d(?:\.\d)?\s+(\d{3})",
        response
    )

    if matches:
        return matches[-1]

    return None


# ============================================================
# SEPARATE HEADERS AND BODY
# ============================================================

def split_response(response):

    if not response:
        return "", ""

    # Find the final header/body separator.
    # Multiple header blocks can exist because of redirects.

    parts = re.split(r"\r?\n\r?\n", response)

    if len(parts) >= 2:

        headers = "\n".join(parts[:-1])
        body = parts[-1]

        return headers, body

    return response, ""


# ============================================================
# EXTRACT PAGE TITLE
# ============================================================

def get_title(body):

    if not body:
        return None

    match = re.search(
        r"<title[^>]*>(.*?)</title>",
        body,
        re.IGNORECASE | re.DOTALL
    )

    if match:

        title = re.sub(
            r"\s+",
            " ",
            match.group(1)
        ).strip()

        return title

    return None


# ============================================================
# NORMALIZE BODY
# ============================================================

def normalize_body(body):

    if not body:
        return ""

    # Remove whitespace
    body = re.sub(r"\s+", " ", body)

    # Remove dynamic-looking values that can create
    # unnecessary differences between requests
    body = body.lower().strip()

    return body


# ============================================================
# CALCULATE CONTENT SIMILARITY
# ============================================================

def calculate_similarity(body1, body2):

    body1 = normalize_body(body1)
    body2 = normalize_body(body2)

    if not body1 or not body2:
        return 0

    # Exact match
    if body1 == body2:
        return 100

    # Use sequence similarity
    from difflib import SequenceMatcher

    similarity = SequenceMatcher(
        None,
        body1,
        body2
    ).ratio()

    return round(similarity * 100, 2)


# ============================================================
# RESOLVE DOMAIN TO IP
# ============================================================

def resolve_domain(url):

    parsed = urlparse(url)

    hostname = parsed.hostname

    if not hostname:
        return None, None

    try:

        ip = socket.gethostbyname(hostname)

        return hostname, ip

    except socket.gaierror:

        return hostname, None


# ============================================================
# MAIN SCANNER
# ============================================================

def scan_ip_access(url):

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)

    hostname, ip = resolve_domain(url)

    if not hostname or not ip:

        print("\nERROR: Could not resolve the domain.")
        return _result(
            "INCOMPLETE",
            "The scanner did not complete because the domain could not be resolved. "
            "This is not a SAFE or UNSAFE security finding.",
            {"error": "dns_resolution_failed", "hostname": hostname},
        )

    print("\n" + "=" * 75)
    print("          WEBSITE IP ACCESS SECURITY SCANNER")
    print("=" * 75)

    print("Target Domain :", hostname)
    print("Resolved IP   :", ip)

    print("-" * 75)

    # ========================================================
    # DOMAIN REQUEST
    # ========================================================

    print("\n[1] Checking normal domain access...")

    domain_response = curl_request(url)

    if not domain_response:

        print("\nCONNECTION ERROR")
        print("Domain request failed.")
        return _result(
            "INCOMPLETE",
            "The scanner did not complete because the target request failed. "
            "This is not a SAFE or UNSAFE security finding.",
            {"error": "connection_error", "hostname": hostname, "ip": ip},
        )

    domain_headers, domain_body = split_response(
        domain_response
    )

    domain_status = get_status(domain_response)
    domain_title = get_title(domain_body)

    print("    Status :", domain_status)

    if domain_title:
        print("    Title  :", domain_title)
    else:
        print("    Title  : Not detected")

    # ========================================================
    # DIRECT IP HTTP REQUEST
    # ========================================================

    print("\n[2] Checking direct IP access...")

    ip_http_url = "http://" + ip

    ip_response = curl_request(ip_http_url)

    if ip_response:

        ip_headers, ip_body = split_response(
            ip_response
        )

        ip_status = get_status(ip_response)
        ip_title = get_title(ip_body)

        print("    IP URL :", ip_http_url)
        print("    Status :", ip_status)

        if ip_title:
            print("    Title  :", ip_title)
        else:
            print("    Title  : Not detected")

    else:

        ip_response = None
        ip_headers = ""
        ip_body = ""
        ip_status = None
        ip_title = None

        print("    IP URL :", ip_http_url)
        print("    Status : Not accessible")

    # ========================================================
    # COMPARE CONTENT
    # ========================================================

    similarity = 0

    if domain_body and ip_body:

        similarity = calculate_similarity(
            domain_body,
            ip_body
        )

    print("\n[3] Comparing domain and IP responses...")

    print(
        "    Content similarity :",
        str(similarity) + "%"
    )

    if domain_title and ip_title:

        print(
            "    Domain title       :",
            domain_title
        )

        print(
            "    IP title           :",
            ip_title
        )

    # ========================================================
    # DETERMINE RESULT
    # ========================================================

    # Strong evidence:
    # - Domain is working
    # - IP is also working
    # - Content is highly similar
    #
    # 90% is used as a conservative similarity threshold
    # for this basic scanner.

    potential_exposure = False

    if (
        domain_status
        and domain_status.startswith("2")
        and ip_status
        and ip_status.startswith("2")
        and similarity >= 90
    ):

        potential_exposure = True

    # ========================================================
    # FINAL OUTPUT
    # ========================================================

    print("\n" + "=" * 75)

    if potential_exposure:

        print("OVERALL STATUS : UNSAFE")

        print("\nSECURITY ISSUE DETECTED")
        print("-" * 75)

        print(
            "The website appears to be directly accessible "
            "through its IP address."
        )

        print("\nEvidence:")

        print(
            f"  Domain : https://{hostname}"
        )

        print(
            f"  IP     : {ip}"
        )

        print(
            f"  Domain response : HTTP {domain_status}"
        )

        print(
            f"  IP response     : HTTP {ip_status}"
        )

        print(
            f"  Content similarity : {similarity}%"
        )

        if domain_title:
            print(
                f"  Domain page title  : {domain_title}"
            )

        if ip_title:
            print(
                f"  IP page title      : {ip_title}"
            )

        print("\nWHY UNSAFE?")

        print(
            "The same or highly similar website content is "
            "available through the direct IP address."
        )

        print(
            "This may expose the origin server or provide an "
            "alternate path that could bypass security controls "
            "such as a CDN, WAF or access restrictions."
        )

        print("\nRECOMMENDED ACTION")

        print(
            "Review whether direct public access to the IP address "
            "is required. If the IP is an origin server, restrict "
            "direct external access and ensure security controls "
            "cannot be bypassed."
        )

        print("\n" + "=" * 75)
        return _result(
            "UNSAFE",
            "The site appears reachable directly through its resolved IP with highly similar content.",
            {
                "hostname": hostname,
                "ip": ip,
                "domain_status": domain_status,
                "ip_status": ip_status,
                "similarity": similarity,
                "domain_title": domain_title,
                "ip_title": ip_title,
            },
            [f"IP {ip} returned similar content ({similarity}%)"],
        )

    print("OVERALL STATUS : SAFE")

    print("\nSECURITY ISSUE DETECTED")
    print("-" * 75)

    print("None detected by this check.")

    print("\nWHY SAFE?")

    if not ip_response:

        print(
            "The website was not directly accessible through "
            "the resolved IP address."
        )

    elif similarity < 90:

        print(
            "The IP address responded, but the returned content "
            "was significantly different from the website "
            "accessed through the domain."
        )

    else:

        print(
            "No direct IP exposure matching the configured "
            "detection criteria was identified."
        )

    print("\n" + "=" * 75)
    return _result(
        "SAFE",
        "No matching direct-IP exposure was identified by the configured test.",
        {
            "hostname": hostname,
            "ip": ip,
            "domain_status": domain_status,
            "ip_status": ip_status,
            "similarity": similarity,
            "ip_accessible": bool(ip_response),
        },
    )


# ============================================================
# MAIN PROGRAM
# ============================================================

if __name__ == "__main__":
    print("\nWebsite IP Access Security Scanner")
    print("---------------------------------")

    url = input("Enter target URL: ").strip()

    if not url:

        print("\nERROR: URL cannot be empty.")

    else:

        scan_ip_access(url)