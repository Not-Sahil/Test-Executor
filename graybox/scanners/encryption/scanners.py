"""Gray-Box Encryption Category Scanners (GB-ENC-01 through GB-ENC-08)."""
from __future__ import annotations

import datetime
import re
import socket
import ssl
from urllib.parse import urljoin, urlparse

from graybox.models import ResultStatus
from graybox.scanners.common import BaseGrayBoxScanner


class GBENC01_TLSVersions(BaseGrayBoxScanner):
    testcase_id = "GB-ENC-01"
    name = "SSL/TLS versions, algorithms, and key length"
    category = "Encryption"

    def execute(self):
        for p in self.payloads:
            self.mark_payload_executed(p)

        parsed = urlparse(self.config.target_url)
        if parsed.scheme != "https":
            return self.build_result(ResultStatus.UNSAFE, "Target is not using HTTPS; SSL/TLS encryption is disabled.")

        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or 443

        try:
            ctx = ssl.create_default_context()
            if not self.config.verify_tls:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=self.config.timeout_seconds) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    version = ssock.version()
                    cipher = ssock.cipher()

            self.add_evidence(f"Negotiated TLS version: {version}, Cipher: {cipher}")
            self.details["tls_version"] = version
            self.details["cipher"] = cipher

            if version in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
                return self.build_result(ResultStatus.UNSAFE, f"Insecure/legacy protocol version negotiated: {version} (Upgrade to TLS 1.2 or TLS 1.3 required).")

            return self.build_result(ResultStatus.SAFE, f"Strong modern TLS protocol negotiated: {version} with cipher {cipher[0]} ({cipher[2]} bits).")
        except Exception as exc:
            self.add_evidence(f"TLS connection check: {exc}")
            return self.build_result(ResultStatus.REVIEW_REQUIRED, f"Could not negotiate TLS connection: {exc}")


class GBENC02_CertificateValidation(BaseGrayBoxScanner):
    testcase_id = "GB-ENC-02"
    name = "Digital certificate validity, duration, signature, and CN/SAN"
    category = "Encryption"

    def execute(self):
        for p in self.payloads:
            self.mark_payload_executed(p)

        parsed = urlparse(self.config.target_url)
        if parsed.scheme != "https":
            return self.build_result(ResultStatus.UNSAFE, "Target does not use HTTPS; no digital certificate is present.")

        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or 443

        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=self.config.timeout_seconds) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()

            if not cert:
                return self.build_result(ResultStatus.REVIEW_REQUIRED, "Target provided no digital certificate details.")

            not_after = cert.get("notAfter", "")
            san = [entry[1] for entry in cert.get("subjectAltName", [])]
            self.add_evidence(f"Certificate expires: {not_after}, SAN entries: {san}")
            self.details["cert_expiry"] = not_after
            self.details["san"] = san

            return self.build_result(ResultStatus.SAFE, f"Digital certificate is valid until {not_after} with SAN entries matching hostname.")
        except ssl.SSLCertVerificationError as exc:
            self.add_evidence(f"Certificate verification error: {exc}")
            return self.build_result(ResultStatus.UNSAFE, f"Digital certificate validation failed: {exc.verify_message}")
        except Exception as exc:
            self.add_evidence(f"Certificate query error: {exc}")
            return self.build_result(ResultStatus.REVIEW_REQUIRED, f"Certificate validation inconclusive: {exc}")


class GBENC03_CredentialsOverHTTPS(BaseGrayBoxScanner):
    testcase_id = "GB-ENC-03"
    name = "Credentials delivered only over HTTPS"
    category = "Encryption"

    def execute(self):
        for p in self.payloads:
            self.mark_payload_executed(p)

        login_url = urljoin(self.config.target_url, self.config.login_path)
        resp = self.session.get(login_url)
        if resp is None:
            return self.build_result(ResultStatus.INCOMPLETE, "Unable to load login page to inspect form action.")

        # Check all <form action="..."> in the page
        forms = re.findall(r'<form\b[^>]*\baction\s*=\s*["\']?([^"\'\s>]+)', resp.text, re.I)
        self.add_evidence(f"Discovered form action endpoints: {forms or ['Implicit current URL']}")

        for action in forms:
            if action.lower().startswith("http://"):
                self.add_evidence(f"Plain HTTP form action detected: {action}")
                return self.build_result(ResultStatus.UNSAFE, f"Insecure credential delivery: form action transmits credentials over plain HTTP ({action}).")

        parsed = urlparse(login_url)
        if parsed.scheme != "https":
            return self.build_result(ResultStatus.UNSAFE, "Login page is hosted over plain HTTP; credential submission is unencrypted.")

        return self.build_result(ResultStatus.SAFE, "All login and authentication form actions deliver credentials strictly over HTTPS.")


class GBENC04_LoginFormOverHTTPS(BaseGrayBoxScanner):
    testcase_id = "GB-ENC-04"
    name = "Login form delivered over HTTPS"
    category = "Encryption"

    def execute(self):
        for p in self.payloads:
            self.mark_payload_executed(p)

        login_url = urljoin(self.config.target_url, self.config.login_path)
        parsed = urlparse(login_url)
        self.add_evidence(f"Evaluated login landing URL scheme: {parsed.scheme}")

        if parsed.scheme != "https":
            return self.build_result(ResultStatus.UNSAFE, f"Login landing page is served over unencrypted HTTP: {login_url}")

        return self.build_result(ResultStatus.SAFE, f"Login landing page is securely delivered over HTTPS ({login_url}).")


class GBENC05_SessionTokensOverHTTPS(BaseGrayBoxScanner):
    testcase_id = "GB-ENC-05"
    name = "Session tokens delivered only over HTTPS"
    category = "Encryption"

    def execute(self):
        for p in self.payloads:
            self.mark_payload_executed(p)

        resp = self.session.get(self.config.target_url)
        if resp is None:
            return self.build_result(ResultStatus.INCOMPLETE, "Target did not respond.")

        set_cookies = resp.headers.get("Set-Cookie", "")
        if not set_cookies:
            # Also check login endpoint
            login_url = urljoin(self.config.target_url, self.config.login_path)
            r2 = self.session.get(login_url)
            if r2:
                set_cookies = r2.headers.get("Set-Cookie", "")

        if not set_cookies:
            return self.build_result(ResultStatus.SAFE, "No cookies set on initial unauthenticated landing page.")

        self.add_evidence(f"Set-Cookie header observed: {set_cookies}")
        if "secure" not in set_cookies.lower():
            return self.build_result(ResultStatus.UNSAFE, "One or more session/auth cookies are missing the 'Secure' attribute.")

        return self.build_result(ResultStatus.SAFE, "All observed cookies include the 'Secure' attribute.")


class GBENC06_HSTS(BaseGrayBoxScanner):
    testcase_id = "GB-ENC-06"
    name = "HSTS"
    category = "Encryption"

    def execute(self):
        for p in self.payloads:
            self.mark_payload_executed(p)

        resp = self.session.get(self.config.target_url)
        if resp is None:
            return self.build_result(ResultStatus.INCOMPLETE, "Target did not respond.")

        hsts = resp.headers.get("Strict-Transport-Security", "")
        self.add_evidence(f"Strict-Transport-Security: {hsts or 'Not present'}")

        if not hsts:
            return self.build_result(ResultStatus.UNSAFE, "Strict-Transport-Security (HSTS) header is missing.")

        m = re.search(r"max-age=(\d+)", hsts, re.I)
        if m:
            max_age = int(m.group(1))
            self.details["hsts_max_age"] = max_age
            if max_age < 31536000:
                return self.build_result(ResultStatus.REVIEW_REQUIRED, f"HSTS max-age is {max_age} seconds (recommended is >= 31536000, 1 year).")

        return self.build_result(ResultStatus.SAFE, f"HSTS is properly configured: {hsts}")


class GBENC07_SensitiveInfoInURL(BaseGrayBoxScanner):
    testcase_id = "GB-ENC-07"
    name = "Sensitive information through URL"
    category = "Encryption"

    def execute(self):
        for p in self.payloads:
            self.mark_payload_executed(p)

        parsed = urlparse(self.config.target_url)
        login_url = urljoin(self.config.target_url, self.config.login_path)
        resp = self.session.get(login_url)

        findings = []
        sensitive_keys = ["password", "token", "secret", "auth", "sessionid", "api_key", "ssn", "pin"]
        if resp and resp.text:
            links = re.findall(r'href=["\']([^"\']+)["\']', resp.text, re.I)
            for link in links:
                q = urlparse(link).query.lower()
                for key in sensitive_keys:
                    if f"{key}=" in q:
                        findings.append(f"Exposed '{key}' in URL: {link}")
                        self.add_evidence(f"Sensitive query key '{key}' found in URL: {link}")

        if findings:
            self.details["url_exposures"] = findings
            return self.build_result(ResultStatus.UNSAFE, f"Sensitive parameters found in GET request URLs: {len(findings)} occurrence(s).")

        return self.build_result(ResultStatus.SAFE, "No credentials, tokens, or sensitive parameters observed in URLs.")


class GBENC08_SSLStripping(BaseGrayBoxScanner):
    testcase_id = "GB-ENC-08"
    name = "SSL stripping / HTTPS downgrade resistance"
    category = "Encryption"

    def execute(self):
        for p in self.payloads:
            self.mark_payload_executed(p)

        parsed = urlparse(self.config.target_url)
        http_url = f"http://{parsed.hostname or '127.0.0.1'}:{80 if parsed.port in (443, None) else parsed.port}"

        resp = self.session.get(http_url, allow_redirects=False, timeout=5.0)
        if resp is None:
            return self.build_result(ResultStatus.SAFE, "Plain HTTP port 80 is closed or not reachable; SSL stripping cannot be performed.")

        self.add_evidence(f"Plain HTTP probe status code: {resp.status_code}")
        if resp.status_code in (301, 308):
            loc = resp.headers.get("Location", "")
            self.add_evidence(f"Redirect Location: {loc}")
            if loc.startswith("https://"):
                return self.build_result(ResultStatus.SAFE, f"Application enforces permanent redirect (HTTP {resp.status_code}) to HTTPS.")
        elif resp.status_code == 200:
            return self.build_result(ResultStatus.UNSAFE, "Application serves unencrypted content over HTTP on port 80 without redirecting to HTTPS.")

        return self.build_result(ResultStatus.REVIEW_REQUIRED, f"Plain HTTP responded with status {resp.status_code}; verify HTTPS redirect policy.")
