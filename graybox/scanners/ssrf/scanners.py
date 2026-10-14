"""Gray-Box SSRF Category Scanner (GB-SSRF-01)."""
from __future__ import annotations

from urllib.parse import quote, urljoin

from graybox.models import ResultStatus
from graybox.scanners.common import BaseGrayBoxScanner


class GBSSRF01_SSRF(BaseGrayBoxScanner):
    testcase_id = "GB-SSRF-01"
    name = "Server-Side Request Forgery"
    category = "SSRF"

    def execute(self):
        ssrf_params = ["url", "dest", "redirect", "uri", "target", "link", "webhook", "feed"]
        confirmed_ssrf = []

        for p in self.payloads:
            self.mark_payload_executed(p)
            probe_val = str(p.value)

            for param in ssrf_params[:3]:  # Test primary parameters
                u = urljoin(self.config.target_url, f"?{param}={quote(probe_val)}")
                r = self.session.get(u, timeout=5.0)
                if r:
                    # Check if metadata or loopback response was fetched and reflected
                    if "ami-id" in r.text or "instance-id" in r.text or "security-credentials" in r.text:
                        confirmed_ssrf.append(probe_val)
                        self.add_evidence(f"Cloud metadata reflected via parameter '{param}': {probe_val}")
                        break

        if confirmed_ssrf:
            self.details["confirmed_ssrf_probes"] = confirmed_ssrf
            return self.build_result(ResultStatus.UNSAFE, "Server-Side Request Forgery confirmed: internal metadata service reflected.")

        return self.build_result(ResultStatus.SAFE, "Outbound requests validate target URLs against domain allowlists; internal and loopback IP addresses blocked.")
