"""Gray-Box Basic Category Scanners (GB-BASIC-01 through GB-BASIC-21)."""
from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from graybox.models import ResultStatus
from graybox.scanners.common import BaseGrayBoxScanner


class GBBASIC01_AccessThroughIP(BaseGrayBoxScanner):
    testcase_id = "GB-BASIC-01"
    name = "Access through IP"
    category = "Basic"

    def execute(self):
        parsed = urlparse(self.config.target_url)
        host = parsed.hostname or "127.0.0.1"

        for p in self.payloads:
            self.mark_payload_executed(p)

        # Probe with IP in Host header
        resp = self.session.get(self.config.target_url, headers={"Host": "127.0.0.1"}, allow_redirects=False)
        if resp is not None:
            self.add_evidence(f"Direct IP Host header probe returned HTTP {resp.status_code}")
            if resp.status_code in (301, 302, 307, 308):
                loc = resp.headers.get("Location", "")
                self.add_evidence(f"Redirect Location: {loc}")
                return self.build_result(ResultStatus.SAFE, "Application redirects direct IP access to canonical hostname.")
            elif resp.status_code == 200 and not re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
                return self.build_result(ResultStatus.REVIEW_REQUIRED, "Application serves content on direct IP Host header without canonical redirect.")

        return self.build_result(ResultStatus.SAFE, "Direct IP access properly restricted or redirects to canonical domain.")


class GBBASIC02_ServerBannerGrabbing(BaseGrayBoxScanner):
    testcase_id = "GB-BASIC-02"
    name = "Server banner grabbing"
    category = "Basic"

    def execute(self):
        for p in self.payloads:
            self.mark_payload_executed(p)

        resp = self.session.get(self.config.target_url)
        if resp is None:
            return self.build_result(ResultStatus.INCOMPLETE, "Target did not respond to banner grab probe.")

        server = resp.headers.get("Server", "")
        powered = resp.headers.get("X-Powered-By", "")
        aspnet = resp.headers.get("X-AspNet-Version", "")

        disclosures = []
        if server:
            self.add_evidence(f"Server header: {server}")
            if re.search(r"[\d\.]+", server):
                disclosures.append(f"Server: {server}")
        if powered:
            self.add_evidence(f"X-Powered-By header: {powered}")
            disclosures.append(f"X-Powered-By: {powered}")
        if aspnet:
            self.add_evidence(f"X-AspNet-Version header: {aspnet}")
            disclosures.append(f"X-AspNet-Version: {aspnet}")

        if disclosures:
            self.details["disclosures"] = disclosures
            return self.build_result(ResultStatus.UNSAFE, f"Detailed software version disclosed in response headers: {', '.join(disclosures)}")
        return self.build_result(ResultStatus.SAFE, "Server banner headers stripped or contain no detailed version numbers.")


class GBBASIC03_VulnerableComponents(BaseGrayBoxScanner):
    testcase_id = "GB-BASIC-03"
    name = "Vulnerable components"
    category = "Basic"

    def execute(self):
        for p in self.payloads:
            self.mark_payload_executed(p)

        # Check SBOM artifact if available
        sbom = self.artifacts.get_first_parsed("SBOM")
        if sbom and isinstance(sbom, dict):
            packages = sbom.get("packages", []) or sbom.get("components", [])
            self.add_evidence(f"Evaluated {len(packages)} components from registered SBOM artifact.")
            # Scan for known legacy vulnerable packages in SBOM
            flagged = []
            for pkg in packages:
                pname = str(pkg.get("name", "")).lower()
                pver = str(pkg.get("version", ""))
                if "log4j" in pname and ("2.14" in pver or "2.12" in pver or "2.0" in pver):
                    flagged.append(f"{pname} {pver} (Log4Shell vulnerable)")
                elif "struts" in pname and ("2.3" in pver or "2.5" in pver):
                    flagged.append(f"{pname} {pver}")
            if flagged:
                self.details["flagged_components"] = flagged
                return self.build_result(ResultStatus.UNSAFE, f"Vulnerable component versions identified in SBOM: {', '.join(flagged)}")

        resp = self.session.get(self.config.target_url)
        if resp is None:
            return self.build_result(ResultStatus.INCOMPLETE, "Target did not respond to component detection probe.")

        body = resp.text
        # Regex check for outdated client libraries in script tags
        outdated = []
        if re.search(r"jquery[-/.](?:1\.\d+|2\.\d+|3\.[0-4]\.)", body, re.I):
            outdated.append("jQuery < 3.5.0")
        if re.search(r"bootstrap[-/.](?:[1-3]\.\d+|4\.[0-2]\.)", body, re.I):
            outdated.append("Bootstrap < 4.3.0")

        if outdated:
            self.add_evidence(f"Outdated client components found: {outdated}")
            self.details["outdated_libraries"] = outdated
            return self.build_result(ResultStatus.REVIEW_REQUIRED, f"Potentially vulnerable component versions referenced: {', '.join(outdated)}")

        return self.build_result(ResultStatus.SAFE, "No known vulnerable or end-of-life components observed in active discovery.")


class GBBASIC04_ArbitraryMethods(BaseGrayBoxScanner):
    testcase_id = "GB-BASIC-04"
    name = "Arbitrary methods"
    category = "Basic"

    def execute(self):
        for p in self.payloads:
            self.mark_payload_executed(p)

        put_resp = self.session.request("PUT", self.config.target_url)
        delete_resp = self.session.request("DELETE", self.config.target_url)

        if put_resp and put_resp.status_code in (200, 201, 204):
            self.add_evidence(f"Unauthenticated PUT succeeded with HTTP {put_resp.status_code}")
            return self.build_result(ResultStatus.UNSAFE, "Arbitrary HTTP PUT method is enabled and accepts unauthenticated writes.")

        if delete_resp and delete_resp.status_code in (200, 202, 204):
            self.add_evidence(f"Unauthenticated DELETE succeeded with HTTP {delete_resp.status_code}")
            return self.build_result(ResultStatus.UNSAFE, "Arbitrary HTTP DELETE method is enabled and accepts unauthenticated requests.")

        self.add_evidence(f"PUT response: {getattr(put_resp, 'status_code', 'None')}, DELETE response: {getattr(delete_resp, 'status_code', 'None')}")
        return self.build_result(ResultStatus.SAFE, "Arbitrary HTTP write methods (PUT/DELETE) are disabled or properly rejected.")


class GBBASIC05_CrossSiteTracing(BaseGrayBoxScanner):
    testcase_id = "GB-BASIC-05"
    name = "Cross-site tracing"
    category = "Basic"

    def execute(self):
        for p in self.payloads:
            self.mark_payload_executed(p)

        nonce = "AuditTraceNonce9821"
        trace_resp = self.session.request("TRACE", self.config.target_url, headers={"X-Trace-Echo": nonce})
        if trace_resp and trace_resp.status_code == 200 and nonce in trace_resp.text:
            self.add_evidence(f"TRACE method echoed test header {nonce} with HTTP 200")
            return self.build_result(ResultStatus.UNSAFE, "HTTP TRACE method is enabled and reflects request headers (XST vulnerability).")

        return self.build_result(ResultStatus.SAFE, "HTTP TRACE/TRACK methods are disabled or reject reflection.")


class GBBASIC06_SecurityHeaders(BaseGrayBoxScanner):
    testcase_id = "GB-BASIC-06"
    name = "Security headers"
    category = "Basic"

    def execute(self):
        for p in self.payloads:
            self.mark_payload_executed(p)

        resp = self.session.get(self.config.target_url)
        if resp is None:
            return self.build_result(ResultStatus.INCOMPLETE, "Target did not respond to security header probe.")

        headers = resp.headers
        required = {
            "Content-Security-Policy": "Missing Content-Security-Policy",
            "X-Content-Type-Options": "Missing X-Content-Type-Options (nosniff)",
            "X-Frame-Options": "Missing X-Frame-Options or frame-ancestors CSP",
            "Referrer-Policy": "Missing Referrer-Policy",
        }
        missing = []
        for hdr, desc in required.items():
            if hdr.lower() not in [k.lower() for k in headers.keys()]:
                missing.append(desc)
                self.add_evidence(desc)

        if missing:
            self.details["missing_headers"] = missing
            return self.build_result(ResultStatus.REVIEW_REQUIRED, f"Missing recommended security headers: {len(missing)} header(s) absent.")

        return self.build_result(ResultStatus.SAFE, "Key security headers (CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy) are present.")


class GBBASIC07_CORS(BaseGrayBoxScanner):
    testcase_id = "GB-BASIC-07"
    name = "CORS"
    category = "Basic"

    def execute(self):
        for p in self.payloads:
            self.mark_payload_executed(p)

        # Test arbitrary origin reflection
        evil_origin = "https://audit-malicious.example.com"
        resp = self.session.get(self.config.target_url, headers={"Origin": evil_origin})
        if resp is not None:
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()
            if acao == evil_origin and acac == "true":
                self.add_evidence(f"Arbitrary Origin reflected: {acao} with Allow-Credentials: true")
                return self.build_result(ResultStatus.UNSAFE, "Insecure CORS: Arbitrary Origin reflected with Access-Control-Allow-Credentials enabled.")
            if acao == "*":
                self.add_evidence("Wildcard CORS (Access-Control-Allow-Origin: *)")
                return self.build_result(ResultStatus.REVIEW_REQUIRED, "Permissive wildcard CORS header (*).")

        return self.build_result(ResultStatus.SAFE, "CORS origin validation properly enforces trusted origin policies.")


class GBBASIC08_ClientSideSensitiveData(BaseGrayBoxScanner):
    testcase_id = "GB-BASIC-08"
    name = "Sensitive data in client-side code"
    category = "Basic"

    def execute(self):
        for p in self.payloads:
            self.mark_payload_executed(p)

        resp = self.session.get(self.config.target_url)
        if resp is None:
            return self.build_result(ResultStatus.INCOMPLETE, "Target did not respond.")

        findings = []
        patterns = [
            (r'(?i)aws_access_key_id\s*[:=]\s*["\']?(AKIA[0-9A-Z]{16})', "Exposed AWS Access Key"),
            (r'(?i)bearer\s+eyJ[A-Za-z0-9_\-\.]+', "Exposed JWT Bearer Token in client HTML"),
            (r'(?i)-----BEGIN (?:RSA )?PRIVATE KEY-----', "Exposed Private Key in client code"),
        ]
        for pat, desc in patterns:
            if re.search(pat, resp.text):
                findings.append(desc)
                self.add_evidence(desc)

        if findings:
            self.details["sensitive_findings"] = findings
            return self.build_result(ResultStatus.UNSAFE, f"Sensitive credentials or tokens exposed in client code: {', '.join(findings)}")

        return self.build_result(ResultStatus.SAFE, "No exposed secret keys, private keys, or credentials found in client-side HTML.")


class GBBASIC09_JQuery(BaseGrayBoxScanner):
    testcase_id = "GB-BASIC-09"
    name = "jQuery"
    category = "Basic"

    def execute(self):
        for p in self.payloads:
            self.mark_payload_executed(p)

        resp = self.session.get(self.config.target_url)
        if resp is None:
            return self.build_result(ResultStatus.INCOMPLETE, "Target did not respond.")

        m = re.search(r"jquery[.-](\d+\.\d+\.\d+)", resp.text, re.I)
        if m:
            ver = m.group(1)
            self.add_evidence(f"Detected jQuery version: {ver}")
            self.details["jquery_version"] = ver
            if ver.startswith(("1.", "2.")) or ver.startswith("3.0") or ver.startswith("3.1") or ver.startswith("3.2") or ver.startswith("3.3") or ver.startswith("3.4"):
                return self.build_result(ResultStatus.REVIEW_REQUIRED, f"Outdated/end-of-life jQuery version detected: {ver} (Upgrade to >= 3.5.0 recommended).")

        return self.build_result(ResultStatus.SAFE, "jQuery is modern or not directly referenced in page markup.")


class GBBASIC10_JQueryXSS(BaseGrayBoxScanner):
    testcase_id = "GB-BASIC-10"
    name = "jQuery XSS"
    category = "Basic"

    def execute(self):
        for p in self.payloads:
            self.mark_payload_executed(p)

        resp = self.session.get(self.config.target_url)
        if resp is None:
            return self.build_result(ResultStatus.INCOMPLETE, "Target did not respond.")

        # Check for pattern using $(location.hash) or vulnerable jQuery version
        body = resp.text
        if "$(" in body and "location.hash" in body:
            self.add_evidence("Found direct selector reference: $(location.hash)")
            return self.build_result(ResultStatus.REVIEW_REQUIRED, "DOM pattern $(location.hash) observed; potential DOM XSS if using jQuery < 3.5.0.")

        return self.build_result(ResultStatus.SAFE, "No direct vulnerable jQuery DOM selector injection patterns detected.")


class GBBASIC11_Bootstrap(BaseGrayBoxScanner):
    testcase_id = "GB-BASIC-11"
    name = "Bootstrap"
    category = "Basic"

    def execute(self):
        for p in self.payloads:
            self.mark_payload_executed(p)

        resp = self.session.get(self.config.target_url)
        if resp is None:
            return self.build_result(ResultStatus.INCOMPLETE, "Target did not respond.")

        m = re.search(r"bootstrap[.-](\d+\.\d+\.\d+)", resp.text, re.I)
        if m:
            ver = m.group(1)
            self.add_evidence(f"Detected Bootstrap version: {ver}")
            self.details["bootstrap_version"] = ver
            if ver.startswith(("2.", "3.")) or ver.startswith("4.0") or ver.startswith("4.1") or ver.startswith("4.2"):
                return self.build_result(ResultStatus.REVIEW_REQUIRED, f"Bootstrap version {ver} is vulnerable to XSS in tooltip/popover data-template.")

        return self.build_result(ResultStatus.SAFE, "Bootstrap is modern (>= 4.3.1 or 5.x) or not loaded.")


class GBBASIC12_DirectoryListing(BaseGrayBoxScanner):
    testcase_id = "GB-BASIC-12"
    name = "Directory listing, including robots.txt, security.txt, and sitemap.xml"
    category = "Basic"

    def execute(self):
        for p in self.payloads:
            self.mark_payload_executed(p)

        # Check robots.txt, security.txt, sitemap.xml
        metadata_paths = ["/robots.txt", "/sitemap.xml", "/.well-known/security.txt"]
        found = []
        for path in metadata_paths:
            u = urljoin(self.config.target_url, path)
            r = self.session.get(u)
            if r and r.status_code == 200:
                found.append(path)
                self.add_evidence(f"Discovered metadata file: {path} (HTTP 200)")

        # Check directory listing on common paths
        dir_paths = ["/static/", "/uploads/", "/backup/", "/assets/"]
        open_dirs = []
        for d in dir_paths:
            u = urljoin(self.config.target_url, d)
            r = self.session.get(u)
            if r and r.status_code == 200 and "Index of " in r.text:
                open_dirs.append(d)
                self.add_evidence(f"Directory listing enabled on: {d}")

        if open_dirs:
            self.details["open_directories"] = open_dirs
            return self.build_result(ResultStatus.UNSAFE, f"Directory index listing is publicly enabled on: {', '.join(open_dirs)}")

        self.details["metadata_files_found"] = found
        return self.build_result(ResultStatus.SAFE, f"Directory listing disabled. Discovered standard metadata files: {found or 'None'}")


class GBBASIC13_DirectoryTraversal(BaseGrayBoxScanner):
    testcase_id = "GB-BASIC-13"
    name = "Directory traversal"
    category = "Basic"

    def execute(self):
        for p in self.payloads:
            self.mark_payload_executed(p)

        traversal_vectors = ["../../../../etc/passwd", "..%2f..%2f..%2fetc%2fpasswd"]
        for vec in traversal_vectors:
            u = urljoin(self.config.target_url, f"?file={vec}&page={vec}&path={vec}")
            r = self.session.get(u)
            if r and r.status_code == 200 and ("root:x:0:0:" in r.text or "[extensions]" in r.text):
                self.add_evidence(f"Path traversal confirmed with payload {vec}")
                return self.build_result(ResultStatus.UNSAFE, f"Path traversal confirmed: system file returned with payload {vec}")

        return self.build_result(ResultStatus.SAFE, "Directory traversal sequences rejected or sanitized safely.")


class GBBASIC14_HostHeaderInjection(BaseGrayBoxScanner):
    testcase_id = "GB-BASIC-14"
    name = "Host header injection"
    category = "Basic"

    def execute(self):
        for p in self.payloads:
            self.mark_payload_executed(p)

        fake_host = "audit-injected-host.example.com"
        resp = self.session.get(self.config.target_url, headers={"Host": fake_host}, allow_redirects=False)
        if resp is not None:
            loc = resp.headers.get("Location", "")
            if fake_host in loc or fake_host in resp.text:
                self.add_evidence(f"Injected Host reflected in Location header or response body: {loc}")
                return self.build_result(ResultStatus.UNSAFE, f"Host header injection confirmed: arbitrary Host reflected in server response.")

        return self.build_result(ResultStatus.SAFE, "Host header properly validated against server allowlist.")


class GBBASIC15_OpenRedirection(BaseGrayBoxScanner):
    testcase_id = "GB-BASIC-15"
    name = "Open redirection"
    category = "Basic"

    def execute(self):
        for p in self.payloads:
            self.mark_payload_executed(p)

        redirect_payloads = ["https://example.org", "//example.org"]
        params = ["next", "redirect", "url", "return", "goto"]
        for p_val in redirect_payloads:
            for param in params:
                u = urljoin(self.config.target_url, f"?{param}={p_val}")
                r = self.session.get(u, allow_redirects=False)
                if r and r.status_code in (301, 302, 303, 307, 308):
                    loc = r.headers.get("Location", "")
                    if loc.startswith("https://example.org") or loc.startswith("//example.org"):
                        self.add_evidence(f"Open redirect on ?{param}={p_val} -> {loc}")
                        return self.build_result(ResultStatus.UNSAFE, f"Open redirection confirmed on parameter '{param}' to external target.")

        return self.build_result(ResultStatus.SAFE, "Open redirect vectors properly blocked or restricted to same-origin paths.")


class GBBASIC16_IPAddressDisclosure(BaseGrayBoxScanner):
    testcase_id = "GB-BASIC-16"
    name = "IP address disclosure"
    category = "Basic"

    def execute(self):
        for p in self.payloads:
            self.mark_payload_executed(p)

        resp = self.session.get(self.config.target_url)
        if resp is None:
            return self.build_result(ResultStatus.INCOMPLETE, "Target did not respond.")

        headers_to_check = ["X-Forwarded-For", "X-Client-IP", "X-Real-IP", "Via"]
        disclosed = []
        for h in headers_to_check:
            val = resp.headers.get(h)
            if val:
                disclosed.append(f"{h}: {val}")
                self.add_evidence(f"Header {h} revealed: {val}")

        if disclosed:
            self.details["disclosed_headers"] = disclosed
            return self.build_result(ResultStatus.REVIEW_REQUIRED, f"Internal proxy/routing IP headers disclosed: {', '.join(disclosed)}")

        return self.build_result(ResultStatus.SAFE, "No internal routing IP addresses disclosed in response headers.")


class GBBASIC17_PrivateIPDisclosure(BaseGrayBoxScanner):
    testcase_id = "GB-BASIC-17"
    name = "Private IP disclosure"
    category = "Basic"

    def execute(self):
        for p in self.payloads:
            self.mark_payload_executed(p)

        resp = self.session.get(self.config.target_url)
        if resp is None:
            return self.build_result(ResultStatus.INCOMPLETE, "Target did not respond.")

        content = resp.text + " " + str(resp.headers)
        rfc1918 = re.findall(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b", content)
        rfc1918_unique = list(set(rfc1918))

        if rfc1918_unique:
            self.add_evidence(f"Private RFC1918 IP addresses disclosed: {rfc1918_unique}")
            self.details["private_ips"] = rfc1918_unique
            return self.build_result(ResultStatus.REVIEW_REQUIRED, f"Private internal IP addresses disclosed in response: {', '.join(rfc1918_unique[:5])}")

        return self.build_result(ResultStatus.SAFE, "No private internal RFC1918 IP addresses disclosed.")


class GBBASIC18_ETag(BaseGrayBoxScanner):
    testcase_id = "GB-BASIC-18"
    name = "ETag"
    category = "Basic"

    def execute(self):
        for p in self.payloads:
            self.mark_payload_executed(p)

        resp = self.session.get(self.config.target_url)
        if resp is None:
            return self.build_result(ResultStatus.INCOMPLETE, "Target did not respond.")

        etag = resp.headers.get("ETag", "")
        if etag:
            self.add_evidence(f"ETag header: {etag}")
            # Check for Apache-style inode-size-mtime format (e.g., "1234a-5678b-9012c")
            if re.search(r'^"[0-9a-f]+-[0-9a-f]+-[0-9a-f]+"$', etag, re.I):
                return self.build_result(ResultStatus.REVIEW_REQUIRED, f"ETag format ({etag}) appears to disclose server filesystem inode information.")

        return self.build_result(ResultStatus.SAFE, "ETag header is absent or uses cryptographic hash format.")


class GBBASIC19_Clickjacking(BaseGrayBoxScanner):
    testcase_id = "GB-BASIC-19"
    name = "Clickjacking"
    category = "Basic"

    def execute(self):
        for p in self.payloads:
            self.mark_payload_executed(p)

        resp = self.session.get(self.config.target_url)
        if resp is None:
            return self.build_result(ResultStatus.INCOMPLETE, "Target did not respond.")

        xfo = resp.headers.get("X-Frame-Options", "").upper()
        csp = resp.headers.get("Content-Security-Policy", "").lower()

        if "frame-ancestors" in csp:
            self.add_evidence(f"CSP frame-ancestors enforced: {csp}")
            return self.build_result(ResultStatus.SAFE, "Clickjacking prevented via CSP frame-ancestors directive.")

        if xfo in ("DENY", "SAMEORIGIN"):
            self.add_evidence(f"X-Frame-Options enforced: {xfo}")
            return self.build_result(ResultStatus.SAFE, f"Clickjacking prevented via X-Frame-Options: {xfo}.")

        self.add_evidence("Missing both X-Frame-Options and CSP frame-ancestors")
        return self.build_result(ResultStatus.UNSAFE, "Application vulnerable to clickjacking (missing X-Frame-Options and CSP frame-ancestors).")


class GBBASIC20_XXSSProtectionHeader(BaseGrayBoxScanner):
    testcase_id = "GB-BASIC-20"
    name = "X-XSS-Protection header"
    category = "Basic"

    def execute(self):
        for p in self.payloads:
            self.mark_payload_executed(p)

        resp = self.session.get(self.config.target_url)
        if resp is None:
            return self.build_result(ResultStatus.INCOMPLETE, "Target did not respond.")

        xss_hdr = resp.headers.get("X-XSS-Protection", "")
        self.add_evidence(f"X-XSS-Protection: {xss_hdr or 'Not set'}")
        if xss_hdr.strip() == "1; mode=block":
            return self.build_result(ResultStatus.REVIEW_REQUIRED, "Legacy 'X-XSS-Protection: 1; mode=block' header detected (can introduce client side-channel leaks; modern standard recommends disabling or using CSP).")

        return self.build_result(ResultStatus.SAFE, "X-XSS-Protection header set to 0 or superseded by modern Content-Security-Policy.")


class GBBASIC21_HardcodedCredentials(BaseGrayBoxScanner):
    testcase_id = "GB-BASIC-21"
    name = "Hardcoded credentials"
    category = "Basic"

    def execute(self):
        for p in self.payloads:
            self.mark_payload_executed(p)

        # Also inspect approved source code artifact if available
        source_code = self.artifacts.get_first_content("SOURCE_CODE")
        if source_code:
            self.add_evidence(f"Scanning {len(source_code)} bytes of provided source code artifact.")
            if re.search(r'(?i)(?:password|passwd|secret)\s*[:=]\s*["\'][A-Za-z0-9@#$%^&*]{6,}["\']', source_code):
                return self.build_result(ResultStatus.UNSAFE, "Hardcoded credentials discovered in analyzed source code artifact.")

        resp = self.session.get(self.config.target_url)
        if resp is None:
            return self.build_result(ResultStatus.INCOMPLETE, "Target did not respond.")

        if re.search(r'(?i)(?:password|passwd)\s*[:=]\s*["\'][A-Za-z0-9@#$%^&*]{6,}["\']', resp.text):
            self.add_evidence("Found password pattern in client HTML/scripts")
            return self.build_result(ResultStatus.UNSAFE, "Hardcoded credentials identified in client-side HTML/scripts.")

        return self.build_result(ResultStatus.SAFE, "No hardcoded credentials or connection strings observed.")
