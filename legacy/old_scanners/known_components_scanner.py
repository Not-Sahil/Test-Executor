from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from html.parser import HTMLParser
from typing import Optional
from urllib.parse import urljoin, urlparse

import requests

DEFAULT_TIMEOUT = 8.0
MAX_JS_ASSETS = 12
MAX_JS_BYTES = 750_000

VERSION_RE = re.compile(r"(?<!\d)(\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.-]+)?)")
JQUERY_CDN = ("code.jquery.com/jquery", "ajax.googleapis.com/ajax/libs/jquery", "cdnjs.cloudflare.com/ajax/libs/jquery", "cdn.jsdelivr.net/npm/jquery", "unpkg.com/jquery")
BOOTSTRAP_CDN = ("stackpath.bootstrapcdn.com/bootstrap", "maxcdn.bootstrapcdn.com/bootstrap", "cdn.jsdelivr.net/npm/bootstrap", "unpkg.com/bootstrap", "cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap", "cdnjs.cloudflare.com/ajax/libs/bootstrap")

RUNTIME_EXPRESSIONS = {
    "jquery_version": """
        () => { try { return window.jQuery?.fn?.jquery || null; } catch(e) { return null; } }
    """,
    "dollar_jquery_version": """
        () => { try { return window.$?.fn?.jquery || null; } catch(e) { return null; } }
    """,
    "jquery_get_available": """
        () => { try { return !!(window.jQuery && typeof window.jQuery.get === 'function'); } catch(e) { return false; } }
    """,
    "bootstrap_runtime_version": """
        () => { try { return window.jQuery?.fn?.tooltip?.Constructor?.VERSION || null; } catch(e) { return null; } }
    """,
}

@dataclass
class ComponentEvidence:
    component: str
    version: Optional[str]
    method: str
    confidence: str
    evidence: str

@dataclass
class ComponentFinding:
    component: str
    versions: list[str] = field(default_factory=list)
    confidence: str = "LOW"
    methods: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)

@dataclass
class KnownComponentsResult:
    key: str = "known_components"
    name: str = "Known Components"
    status: str = "SAFE"
    summary: str = ""
    details: dict = field(default_factory=dict)
    evidence: list[str] = field(default_factory=list)
    raw_output: str = ""

    def as_dict(self):
        return asdict(self)

class AssetParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.scripts: list[str] = []
        self.ids: list[str] = []
        self.classes: list[str] = []
        self.data_attrs: list[str] = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag.lower() == "script" and a.get("src"):
            self.scripts.append(a["src"])
        if a.get("id"):
            self.ids.append(a["id"])
        if a.get("class"):
            self.classes.extend(a["class"].split())
        self.data_attrs.extend(k.lower() for k in a if k.lower().startswith("data-"))

def norm_url(url: str) -> str:
    if not url:
        return ""
    return url if re.match(r"^https?://", url, re.I) else "https://" + url

def same_origin(a: str, b: str) -> bool:
    x, y = urlparse(a), urlparse(b)
    return (x.scheme.lower(), x.hostname, x.port) == (y.scheme.lower(), y.hostname, y.port)

def version_from_component(text: str, component: str) -> Optional[str]:
    """Extract a likely version for a known client-side component."""
    if not text:
        return None

    if component == "jQuery":
        pattern = (
            r"(?:jquery)[^0-9]{0,12}"
            r"(\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.-]+)?)"
        )

    elif component == "Bootstrap":
        pattern = (
            r"(?:bootstrap)[^0-9]{0,12}"
            r"(\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.-]+)?)"
        )

    else:
        pattern = (
            r"(?<!\d)"
            r"(\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.-]+)?)"
        )

    match = re.search(pattern, text, re.I)
    return match.group(1) if match else None

def script_evidence(page_url: str, scripts: list[str]) -> list[ComponentEvidence]:
    out=[]
    for raw in scripts:
        u=urljoin(page_url, raw); low=u.lower()
        if "jquery" in low:
            v=version_from_component(u,"jQuery")
            out.append(ComponentEvidence("jQuery",v,"script_src","HIGH" if v else "MEDIUM",u))
        if "bootstrap" in low:
            v=version_from_component(u,"Bootstrap")
            out.append(ComponentEvidence("Bootstrap",v,"script_src","HIGH" if v else "MEDIUM",u))
    return out

def cdn_evidence(page_url: str, scripts: list[str]) -> list[ComponentEvidence]:
    out=[]
    for raw in scripts:
        u=urljoin(page_url,raw); low=u.lower()
        if any(x in low for x in JQUERY_CDN):
            out.append(ComponentEvidence("jQuery",version_from_component(u,"jQuery"),"cdn_url","HIGH" if version_from_component(u,"jQuery") else "MEDIUM",u))
        if any(x in low for x in BOOTSTRAP_CDN):
            out.append(ComponentEvidence("Bootstrap",version_from_component(u,"Bootstrap"),"cdn_url","HIGH" if version_from_component(u,"Bootstrap") else "MEDIUM",u))
    return out

def dom_evidence(parser: AssetParser, body: str) -> list[ComponentEvidence]:
    out=[]; ids={x.lower() for x in parser.ids}; classes={x.lower() for x in parser.classes}; attrs=set(parser.data_attrs)
    if "bootstrap" in ids:
        out.append(ComponentEvidence("Bootstrap",None,"dom_id:#bootstrap","LOW",'Found DOM id="bootstrap"'))
    hits=sorted(classes & {"navbar","btn","modal","carousel","dropdown","container-fluid","alert","tooltip"})
    battrs=sorted(attrs & {"data-toggle","data-target","data-bs-toggle","data-bs-target","data-dismiss","data-bs-dismiss"})
    if len(hits)>=2 or battrs:
        out.append(ComponentEvidence("Bootstrap",None,"dom_fingerprint","MEDIUM",f"classes={','.join(hits[:6])}; attributes={','.join(battrs)}"))
    return out

def correlate(items: list[ComponentEvidence]) -> list[ComponentFinding]:
    grouped={}
    for x in items: grouped.setdefault(x.component,[]).append(x)
    out=[]
    for comp, arr in grouped.items():
        versions=sorted({x.version for x in arr if x.version})
        methods=list(dict.fromkeys(x.method for x in arr))
        if any(x.method.startswith("runtime_") for x in arr) and versions: conf="HIGH"
        elif versions and len(methods)>=2: conf="HIGH"
        elif versions: conf="MEDIUM"
        elif len(methods)>=2: conf="MEDIUM"
        else: conf="LOW"
        out.append(ComponentFinding(comp,versions,conf,methods,[x.evidence for x in arr]))
    return out

class KnownComponentsScanner:
    def __init__(self, timeout: float=DEFAULT_TIMEOUT, verify_tls: bool=True):
        self.timeout=timeout; self.verify_tls=verify_tls; self.s=requests.Session(); self.s.headers["User-Agent"]="SixScan-KnownComponents/1.0"; self.requests_made=0
    def get(self,u):
        try:
            self.requests_made+=1; return self.s.get(u,timeout=self.timeout,verify=self.verify_tls,allow_redirects=True)
        except requests.RequestException:
            return None
    def browser_runtime(self,page_url:str):
        out=[]
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            return out
        try:
            with sync_playwright() as pw:
                b=pw.chromium.launch(headless=True); p=b.new_page(ignore_https_errors=not self.verify_tls)
                p.goto(page_url,wait_until="domcontentloaded",timeout=int(self.timeout*1000)); p.wait_for_timeout(400)
                j=p.evaluate(RUNTIME_EXPRESSIONS["jquery_version"]); d=p.evaluate(RUNTIME_EXPRESSIONS["dollar_jquery_version"]); g=p.evaluate(RUNTIME_EXPRESSIONS["jquery_get_available"]); bs=p.evaluate(RUNTIME_EXPRESSIONS["bootstrap_runtime_version"])
                if j: out.append(ComponentEvidence("jQuery",str(j),"runtime_jquery.fn.jquery","HIGH",f"jQuery.fn.jquery returned {j}"))
                elif d: out.append(ComponentEvidence("jQuery",str(d),"runtime_$.fn.jquery","HIGH",f"$.fn.jquery returned {d}"))
                elif g: out.append(ComponentEvidence("jQuery",None,"runtime_$.get_availability","MEDIUM","$.get is available"))
                if bs: out.append(ComponentEvidence("Bootstrap",str(bs),"runtime_$.fn.tooltip.Constructor.VERSION","HIGH",f"Bootstrap runtime version returned {bs}"))
                for u in p.evaluate("() => performance.getEntriesByType('resource').map(x=>x.name)") or []:
                    if "jquery" in u.lower(): out.append(ComponentEvidence("jQuery",version_from_component(u,"jQuery"),"browser_resource","HIGH",u))
                    if "bootstrap" in u.lower(): out.append(ComponentEvidence("Bootstrap",version_from_component(u,"Bootstrap"),"browser_resource","HIGH",u))
                b.close()
        except Exception:
            pass
        return out
    def scan(self,target,use_browser_runtime=True):
        target=norm_url(target); r=self.get(target)
        if not r: return KnownComponentsResult(status="INCOMPLETE",summary="The target page could not be retrieved. This is not a SAFE or UNSAFE finding.",details={"error":"request_failed","target":target})
        final=r.url or target; body=r.text or ""; ctype=r.headers.get("Content-Type","")
        if "html" not in ctype.lower() and "<html" not in body[:5000].lower():
            return KnownComponentsResult(status="INCOMPLETE",summary="The target response is not an HTML page, so client-side component detection was not applicable.",details={"http_status":r.status_code,"content_type":ctype})
        p=AssetParser(); p.feed(body)
        ev=script_evidence(final,p.scripts)+cdn_evidence(final,p.scripts)+dom_evidence(p,body)
        assets=[]
        for x in p.scripts:
            u=urljoin(final,x)
            if same_origin(final,u): assets.append(u)
        for u in list(dict.fromkeys(assets))[:MAX_JS_ASSETS]:
            jr=self.get(u)
            if jr and len(jr.content)<=MAX_JS_BYTES:
                low=jr.text.lower()
                if "jquery" in low: ev.append(ComponentEvidence("jQuery",version_from_component(jr.text,"jQuery"),"js_bundle_fingerprint","MEDIUM",f"jQuery signatures found in {u}"))
                if "bootstrap" in low and "tooltip" in low and "popover" in low: ev.append(ComponentEvidence("Bootstrap",version_from_component(jr.text,"Bootstrap"),"js_bundle_fingerprint","MEDIUM",f"Bootstrap signatures found in {u}"))
        if use_browser_runtime: ev += self.browser_runtime(final)
        uniq=[]; seen=set()
        for x in ev:
            k=(x.component,x.version,x.method,x.evidence)
            if k not in seen: seen.add(k); uniq.append(x)
        findings=correlate(uniq)
        details={"target":target,"final_url":final,"http_status":r.status_code,"content_type":ctype,"requests_made":self.requests_made,"components":[asdict(x) for x in findings]}
        if findings:
            summary="Known client-side components were identified. Component identification alone does not establish a vulnerability. " + " ; ".join(f"{x.component}: {', '.join(x.versions) if x.versions else 'version not determined'} ({x.confidence})" for x in findings)
        else:
            summary="No supported known-component fingerprints were identified with sufficient evidence on the inspected page."
        evidence=[f"{x.component} | {x.method} | {x.confidence} | {x.version or 'version unknown'} | {x.evidence}" for x in uniq]
        return KnownComponentsResult(status="SAFE",summary=summary,details=details,evidence=evidence,raw_output=json.dumps(details,indent=2))

def scan_known_components(url:str,timeout:float=DEFAULT_TIMEOUT,use_browser_runtime=True):
    return KnownComponentsScanner(timeout=timeout).scan(url,use_browser_runtime)

if __name__ == "__main__":
    import argparse
    ap=argparse.ArgumentParser(); ap.add_argument("url"); ap.add_argument("--no-browser",action="store_true"); a=ap.parse_args(); result=scan_known_components(a.url,use_browser_runtime=not a.no_browser); print(json.dumps(result.as_dict(),indent=2))
