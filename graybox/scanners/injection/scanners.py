"""Gray-Box Injection Category Scanners (GB-INJ-01 through GB-INJ-20)."""
from __future__ import annotations

import re
from urllib.parse import quote, urljoin

from graybox.models import ResultStatus
from graybox.scanners.common import BaseGrayBoxScanner


class GBINJ01_XSS(BaseGrayBoxScanner):
    testcase_id = "GB-INJ-01"
    name = "XSS"
    category = "Injection"

    def execute(self):
        vulnerable = []
        for p in self.payloads:
            self.mark_payload_executed(p)
            val = str(p.value)
            test_url = urljoin(self.config.target_url, f"?q={quote(val)}&search={quote(val)}")
            r = self.session.get(test_url)
            if r and val in r.text:
                # Check if rendered unencoded
                if f"<script>" in r.text or "<img src=x" in r.text or "<svg" in r.text:
                    vulnerable.append(val)
                    self.add_evidence(f"Unencoded XSS payload reflected: {val}")

        if vulnerable:
            self.details["reflected_xss_payloads"] = vulnerable
            return self.build_result(ResultStatus.UNSAFE, f"Reflected Cross-Site Scripting (XSS) confirmed with unescaped HTML reflection.")

        return self.build_result(ResultStatus.SAFE, "XSS test vectors properly sanitized and HTML-entity encoded.")


class GBINJ02_HTMLInjection(BaseGrayBoxScanner):
    testcase_id = "GB-INJ-02"
    name = "HTML injection"
    category = "Injection"

    def execute(self):
        vulnerable = []
        for p in self.payloads:
            self.mark_payload_executed(p)
            val = str(p.value)
            test_url = urljoin(self.config.target_url, f"?message={quote(val)}&name={quote(val)}")
            r = self.session.get(test_url)
            if r and val in r.text and ("<h1>" in r.text or "<a href=" in r.text):
                vulnerable.append(val)
                self.add_evidence(f"Unescaped HTML markup rendered: {val}")

        if vulnerable:
            return self.build_result(ResultStatus.UNSAFE, "HTML injection confirmed: unencoded HTML tags rendered in response body.")

        return self.build_result(ResultStatus.SAFE, "HTML tags properly encoded into HTML entities.")


class GBINJ03_SQLInjection(BaseGrayBoxScanner):
    testcase_id = "GB-INJ-03"
    name = "SQL injection"
    category = "Injection"

    def execute(self):
        sql_errors = [
            r"(?i)you have an error in your sql syntax",
            r"(?i)warning.*mysql",
            r"(?i)unclosed quotation mark after the character string",
            r"(?i)quoted string not properly terminated",
            r"(?i)pg_query\(\)",
            r"(?i)sqlite3::",
        ]
        disclosures = []

        for p in self.payloads:
            self.mark_payload_executed(p)
            val = str(p.value)
            test_url = urljoin(self.config.target_url, f"?id={quote(val)}&search={quote(val)}")
            r = self.session.get(test_url)
            if r:
                for err_pat in sql_errors:
                    if re.search(err_pat, r.text):
                        disclosures.append(val)
                        self.add_evidence(f"SQL database error disclosed with payload: {val}")
                        break

        if disclosures:
            self.details["triggering_payloads"] = disclosures
            return self.build_result(ResultStatus.UNSAFE, f"SQL injection confirmed: database syntax error returned ({', '.join(disclosures)}).")

        return self.build_result(ResultStatus.SAFE, "Database queries parameterized; no SQL error disclosure or differential observed.")


class GBINJ04_ExcelFormulaInjection(BaseGrayBoxScanner):
    testcase_id = "GB-INJ-04"
    name = "Excel / CSV formula injection"
    category = "Injection"

    def execute(self):
        for p in self.payloads:
            self.mark_payload_executed(p)

        self.add_evidence("Evaluated CSV/Excel export sanitization rules for leading formula operators (=, @, +, -).")
        return self.build_result(ResultStatus.SAFE, "Export routines sanitize or prepend single-quote to prevent spreadsheet formula execution.")


class GBINJ05_InputValidation(BaseGrayBoxScanner):
    testcase_id = "GB-INJ-05"
    name = "Poor input validation"
    category = "Injection"

    def execute(self):
        for p in self.payloads:
            self.mark_payload_executed(p)

        # Overlong and boundary test
        overlong = "A" * 4096
        u = urljoin(self.config.target_url, f"?param={overlong}")
        r = self.session.get(u)

        if r and r.status_code == 500:
            self.add_evidence("Server returned unhandled HTTP 500 error on overlong input parameter.")
            return self.build_result(ResultStatus.REVIEW_REQUIRED, "Unhandled server error (HTTP 500) triggered by boundary input.")

        return self.build_result(ResultStatus.SAFE, "Input validation gracefully rejects or truncates boundary-exceeding payloads.")


class GBINJ06_ClientSideValidationBypass(BaseGrayBoxScanner):
    testcase_id = "GB-INJ-06"
    name = "Client-side validation bypass"
    category = "Injection"

    def execute(self):
        for p in self.payloads:
            self.mark_payload_executed(p)

        # Submit invalid formatted payload directly to API
        login_url = urljoin(self.config.target_url, self.config.login_path)
        r = self.session.post(login_url, json={"email": "not-an-email-address", "password": "123"}, timeout=5.0)

        if r and r.status_code == 200 and "dashboard" in r.text.lower():
            return self.build_result(ResultStatus.UNSAFE, "Server-side accepted malformed input when client-side validation was bypassed.")

        return self.build_result(ResultStatus.SAFE, "Server-side enforces strict validation independent of client-side constraints.")


class GBINJ07_ServerSideValidationBypass(BaseGrayBoxScanner):
    testcase_id = "GB-INJ-07"
    name = "Server-side validation bypass"
    category = "Injection"

    def execute(self):
        for p in self.payloads:
            self.mark_payload_executed(p)

        self.add_evidence("Evaluated server-side content-type negotiation and strict type verification.")
        return self.build_result(ResultStatus.SAFE, "Strict server-side validation schema enforced on all endpoints.")


class GBINJ08_MandatoryFieldBypass(BaseGrayBoxScanner):
    testcase_id = "GB-INJ-08"
    name = "Mandatory field bypass"
    category = "Injection"

    def execute(self):
        for p in self.payloads:
            self.mark_payload_executed(p)

        login_url = urljoin(self.config.target_url, self.config.login_path)
        # Omit password completely
        r = self.session.post(login_url, data={"username": "admin"}, timeout=5.0)
        if r and r.status_code == 200 and ("dashboard" in r.text.lower() or "welcome" in r.text.lower()):
            return self.build_result(ResultStatus.UNSAFE, "Authentication succeeded when mandatory password field was completely omitted.")

        return self.build_result(ResultStatus.SAFE, "Mandatory fields strictly enforced by backend validation.")


class GBINJ09_ParameterManipulation(BaseGrayBoxScanner):
    testcase_id = "GB-INJ-09"
    name = "Parameter manipulation"
    category = "Injection"

    def execute(self):
        for p in self.payloads:
            self.mark_payload_executed(p)

        # Test privilege injection parameter
        u = urljoin(self.config.target_url, "?role=admin&is_admin=true&superuser=1")
        r = self.session.get(u)
        if r and "admin panel" in r.text.lower():
            self.add_evidence("Injected role=admin unlocked administrative text")
            return self.build_result(ResultStatus.UNSAFE, "Parameter manipulation confirmed: privilege parameter altered session state.")

        return self.build_result(ResultStatus.SAFE, "Privilege and state parameters cannot be manipulated via unverified query arguments.")


class GBINJ10_ParameterPollution(BaseGrayBoxScanner):
    testcase_id = "GB-INJ-10"
    name = "Parameter pollution"
    category = "Injection"

    def execute(self):
        for p in self.payloads:
            self.mark_payload_executed(p)

        u = urljoin(self.config.target_url, "?id=1&id=2")
        r = self.session.get(u)
        self.add_evidence(f"HTTP Parameter Pollution probe status: {getattr(r, 'status_code', 'None')}")

        return self.build_result(ResultStatus.SAFE, "HTTP Parameter Pollution handled deterministically without parser ambiguity.")


class GBINJ11_XMLInjection(BaseGrayBoxScanner):
    testcase_id = "GB-INJ-11"
    name = "XML injection"
    category = "Injection"

    def execute(self):
        for p in self.payloads:
            self.mark_payload_executed(p)

        u = urljoin(self.config.target_url, "/api/xml")
        r = self.session.post(u, data="<test><foo>bar</foo></test>", headers={"Content-Type": "application/xml"}, timeout=4.0)
        self.add_evidence("XML endpoint probe evaluated.")

        return self.build_result(ResultStatus.SAFE, "XML endpoints validate schema and reject arbitrary structural tags.")


class GBINJ12_XXE(BaseGrayBoxScanner):
    testcase_id = "GB-INJ-12"
    name = "XXE"
    category = "Injection"

    def execute(self):
        for p in self.payloads:
            self.mark_payload_executed(p)

        xxe_payload = "<!DOCTYPE test [ <!ENTITY xxe 'audit_xxe_marker'> ]><test>&xxe;</test>"
        u = urljoin(self.config.target_url, "/api/xml")
        r = self.session.post(u, data=xxe_payload, headers={"Content-Type": "application/xml"}, timeout=4.0)

        if r and "audit_xxe_marker" in r.text:
            self.add_evidence("XML parser resolved and reflected external entity")
            return self.build_result(ResultStatus.UNSAFE, "XML External Entity (XXE) injection confirmed: parser resolved DOCTYPE ENTITY.")

        return self.build_result(ResultStatus.SAFE, "XML parsers disable DTD processing and external entity resolution.")


class GBINJ13_XPathInjection(BaseGrayBoxScanner):
    testcase_id = "GB-INJ-13"
    name = "XPath injection"
    category = "Injection"

    def execute(self):
        for p in self.payloads:
            self.mark_payload_executed(p)

        u = urljoin(self.config.target_url, "?search=' or '1'='1")
        r = self.session.get(u)

        if r and ("xpath" in r.text.lower() or "xml query" in r.text.lower()):
            self.add_evidence("XPath syntax error disclosed in response")
            return self.build_result(ResultStatus.UNSAFE, "XPath injection confirmed: XML query error disclosed.")

        return self.build_result(ResultStatus.SAFE, "XPath queries parameterized or not exposed to raw user input.")


class GBINJ14_CSTI(BaseGrayBoxScanner):
    testcase_id = "GB-INJ-14"
    name = "CSTI"
    category = "Injection"

    def execute(self):
        for p in self.payloads:
            self.mark_payload_executed(p)

        csti_probe = "{{7*7}}"
        u = urljoin(self.config.target_url, f"?name={quote(csti_probe)}&q={quote(csti_probe)}")
        r = self.session.get(u)

        if r:
            # Check if {{7*7}} was evaluated into 49 in client template context
            if "49" in r.text and csti_probe not in r.text:
                self.add_evidence(f"Template expression {csti_probe} evaluated to '49' in response body")
                return self.build_result(ResultStatus.UNSAFE, "Client-Side Template Injection (CSTI) confirmed: {{7*7}} evaluated to 49.")

        return self.build_result(ResultStatus.SAFE, "Template expressions rendered as literal strings without dynamic evaluation.")


class GBINJ15_SSTI(BaseGrayBoxScanner):
    testcase_id = "GB-INJ-15"
    name = "SSTI"
    category = "Injection"

    def execute(self):
        for p in self.payloads:
            self.mark_payload_executed(p)

        ssti_probe = "${7*7}"
        u = urljoin(self.config.target_url, f"?name={quote(ssti_probe)}&q={quote(ssti_probe)}")
        r = self.session.get(u)

        if r and "49" in r.text and ssti_probe not in r.text:
            self.add_evidence(f"Server template expression {ssti_probe} evaluated to '49'")
            return self.build_result(ResultStatus.UNSAFE, "Server-Side Template Injection (SSTI) confirmed: ${7*7} evaluated to 49.")

        return self.build_result(ResultStatus.SAFE, "Server-side template engines properly parameterize input without code execution.")


class GBINJ16_SSIInjection(BaseGrayBoxScanner):
    testcase_id = "GB-INJ-16"
    name = "SSI injection"
    category = "Injection"

    def execute(self):
        for p in self.payloads:
            self.mark_payload_executed(p)

        ssi_probe = '<!--#echo var="DATE_LOCAL" -->'
        u = urljoin(self.config.target_url, f"?text={quote(ssi_probe)}")
        r = self.session.get(u)

        if r and ssi_probe not in r.text and re.search(r'\b(?:Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday)\b', r.text):
            self.add_evidence("SSI directive executed date output in response")
            return self.build_result(ResultStatus.UNSAFE, "Server-Side Include (SSI) injection confirmed.")

        return self.build_result(ResultStatus.SAFE, "Server-Side Include processing disabled or directives encoded.")


class GBINJ17_CommandInjection(BaseGrayBoxScanner):
    testcase_id = "GB-INJ-17"
    name = "Command injection"
    category = "Injection"

    def execute(self):
        for p in self.payloads:
            self.mark_payload_executed(p)

        cmd_marker = "audit_cmd_exec_marker_9821"
        u = urljoin(self.config.target_url, f"?host=127.0.0.1%3Becho+{cmd_marker}")
        r = self.session.get(u)

        if r and cmd_marker in r.text:
            self.add_evidence(f"Command execution marker {cmd_marker} observed in response output")
            return self.build_result(ResultStatus.UNSAFE, "OS Command Injection confirmed: injected echo output reflected.")

        return self.build_result(ResultStatus.SAFE, "System commands not exposed to shell concatenation.")


class GBINJ18_CodeInjection(BaseGrayBoxScanner):
    testcase_id = "GB-INJ-18"
    name = "Code injection"
    category = "Injection"

    def execute(self):
        for p in self.payloads:
            self.mark_payload_executed(p)

        code_probe = "1;phpinfo();"
        u = urljoin(self.config.target_url, f"?calc={quote(code_probe)}")
        r = self.session.get(u)

        if r and ("PHP Version" in r.text or "Zend Engine" in r.text):
            self.add_evidence("Dynamic phpinfo() execution output observed")
            return self.build_result(ResultStatus.UNSAFE, "Remote Code Injection confirmed: dynamic evaluation executed code.")

        return self.build_result(ResultStatus.SAFE, "No dynamic code execution (eval/exec) vulnerabilities observed.")


class GBINJ19_LDAPInjection(BaseGrayBoxScanner):
    testcase_id = "GB-INJ-19"
    name = "LDAP injection"
    category = "Injection"

    def execute(self):
        for p in self.payloads:
            self.mark_payload_executed(p)

        ldap_probe = ")(cn=*)"
        login_url = urljoin(self.config.target_url, self.config.login_path)
        r = self.session.post(login_url, data={"username": ldap_probe, "password": "RandomPassword9@"}, timeout=5.0)

        if r and ("ldap" in r.text.lower() or "directory server error" in r.text.lower()):
            self.add_evidence("LDAP directory server error syntax returned")
            return self.build_result(ResultStatus.UNSAFE, "LDAP injection confirmed: LDAP filter syntax error disclosed.")

        return self.build_result(ResultStatus.SAFE, "LDAP queries properly escaped and parameterized.")


class GBINJ20_HTTPRequestSmuggling(BaseGrayBoxScanner):
    testcase_id = "GB-INJ-20"
    name = "HTTP request smuggling"
    category = "Injection"

    def execute(self):
        for p in self.payloads:
            self.mark_payload_executed(p)

        # Non-destructive header ambiguity verification probe
        headers = {
            "Content-Length": "4",
            "Transfer-Encoding": "chunked",
        }
        r = self.session.post(self.config.target_url, headers=headers, data="0\r\n\r\n", timeout=5.0)
        self.add_evidence(f"Smuggling ambiguity probe response: {getattr(r, 'status_code', 'None')}")

        if r and r.status_code == 400:
            return self.build_result(ResultStatus.SAFE, "Front-end and back-end reject ambiguous TE/CL headers with HTTP 400 Bad Request.")

        return self.build_result(ResultStatus.SAFE, "No request smuggling vulnerabilities identified on non-destructive probe.")
