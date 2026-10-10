from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlparse

try:
    from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError
except Exception:  # pragma: no cover
    sync_playwright = None
    PlaywrightTimeoutError = Exception

from authentication.browser_memory_heap import scan_heap_snapshot_for_markers
from authentication.browser_memory_models import BrowserMemoryConfig, MemoryObservation, MemoryProbe
from authentication.browser_memory_redaction import redact_mapping, safe_evidence, secret_fingerprint


@dataclass
class BrowserRun:
    observations: list[MemoryObservation] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    heap_supported: bool = False
    heap_examined: bool = False
    heap_issue: bool = False
    direct_issue: bool = False
    storage_issue: bool = False
    authenticated: bool = False


def _same_origin(a: str, b: str) -> bool:
    pa, pb = urlparse(a), urlparse(b)
    return (pa.scheme, pa.netloc) == (pb.scheme, pb.netloc)


def _absolute(base: str, path_or_url: str) -> str:
    raw = (path_or_url or "").strip()
    if not raw:
        return base
    parsed = urlparse(raw)
    if parsed.scheme and parsed.netloc:
        return raw
    return urljoin(base.rstrip("/") + "/", raw.lstrip("/"))


def _looks_login_url(url: str, login_url: str) -> bool:
    a = urlparse(url)
    b = urlparse(login_url)
    return a.netloc == b.netloc and a.path.rstrip("/") == b.path.rstrip("/")


def _find_username_locator(page):
    selectors = [
        'input[autocomplete="username"]',
        'input[name*="username" i]',
        'input[name="user" i]',
        'input[name="uid" i]',
        'input[id="uid" i]',
        'input[name*="email" i]',
        'input[type="email"]',
        'input[id*="username" i]',
        'input[id*="email" i]',
        'input:not([type="password"]):not([type="hidden"]):not([type="submit"]):not([type="button"])',
    ]
    for selector in selectors:
        locator = page.locator(selector).first
        try:
            if locator.count() > 0 and locator.is_visible():
                return locator
        except Exception:
            continue
    return None


def _find_password_locator(page):
    selectors = [
        'input[type="password"]',
        'input[autocomplete="current-password"]',
        'input[name*="password" i]',
        'input[name*="passwd" i]',
    ]
    for selector in selectors:
        locator = page.locator(selector).first
        try:
            if locator.count() > 0 and locator.is_visible():
                return locator
        except Exception:
            continue
    return None


def _fill_without_persisting_autofill(page, username: str, password: str) -> tuple[Any, Any]:
    user = _find_username_locator(page)
    pwd = _find_password_locator(page)
    if user is None or pwd is None:
        raise RuntimeError("visible username/password fields were not discovered")
    user.fill(username)
    pwd.fill(password)
    return user, pwd


def _scan_dom_and_reachable_globals(page, probe: MemoryProbe, cfg: BrowserMemoryConfig, *, phase: str, include_globals: bool) -> list[MemoryObservation]:
    script = r"""
    ({username, password, maxObjects, maxDepth, maxStringLength, includeGlobals}) => {
      const findings = [];
      const seen = new WeakSet();
      let objects = 0;

      function scanPrimitive(value, path) {
        if (typeof value !== 'string') return;
        const clipped = value.slice(0, maxStringLength);
        if (clipped.includes(password)) {
          findings.push({source:'js_reachable', path, matched:'password'});
        }
        if (clipped.includes(username)) {
          findings.push({source:'js_reachable', path, matched:'username'});
        }
      }

      function scan(value, path, depth) {
        if (objects++ >= maxObjects || depth > maxDepth || findings.length >= 20) return;
        const t = typeof value;
        if (t === 'string') { scanPrimitive(value, path); return; }
        if (!value || (t !== 'object' && t !== 'function')) return;
        if (seen.has(value)) return;
        seen.add(value);

        let keys = [];
        try { keys = Object.getOwnPropertyNames(value).slice(0, 80); } catch (_) { return; }
        for (const key of keys) {
          if (findings.length >= 20) break;
          let descriptor = null;
          try { descriptor = Object.getOwnPropertyDescriptor(value, key); } catch (_) { continue; }
          if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, 'value')) continue;
          try { scan(descriptor.value, `${path}.${key}`, depth + 1); } catch (_) {}
        }
      }

      const inputs = Array.from(document.querySelectorAll('input[type="password"], input[type="text"], input[type="email"]'))
        .map((el, i) => ({
          index:i,
          type:el.type,
          name:el.name,
          id:el.id,
          value:String(el.value || '')
        }));

      for (const item of inputs) {
        if (item.value.includes(password)) findings.push({source:'dom_input', path:`input[${item.index}].value`, matched:'password'});
        if (item.value.includes(username)) findings.push({source:'dom_input', path:`input[${item.index}].value`, matched:'username'});
      }

      const text = String(document.documentElement?.textContent || '');
      if (text.includes(password)) findings.push({source:'dom_text', path:'document.textContent', matched:'password'});
      if (text.includes(username)) findings.push({source:'dom_text', path:'document.textContent', matched:'username'});

      if (includeGlobals) {
        try { scan(window, 'window', 0); } catch (_) {}
      }

      return {findings, objectCount:objects};
    }
    """
    try:
        data = page.evaluate(
            script,
            {
                "username": probe.username,
                "password": probe.password,
                "maxObjects": cfg.max_global_objects,
                "maxDepth": cfg.max_global_depth,
                "maxStringLength": cfg.max_string_length,
                "includeGlobals": include_globals,
            },
        )
    except Exception as exc:
        return [
            MemoryObservation(
                phase=phase,
                source="dom_js",
                inspected=False,
                error=f"{type(exc).__name__}: {exc}",
            )
        ]

    observations: list[MemoryObservation] = []
    grouped: dict[str, list[str]] = {}
    for finding in data.get("findings", []):
        grouped.setdefault(finding.get("source", "unknown"), []).append(
            finding.get("path", "")
        )
    if not grouped:
        observations.append(
            MemoryObservation(
                phase=phase,
                source="dom_js",
                inspected=True,
                matched=False,
                confidence="high",
                evidence=[f"DOM/reachable-JS scan completed; visited_objects={data.get('objectCount', 0)}"],
            )
        )
    else:
        for source, paths in grouped.items():
            matched_password = any(
                finding.get("source") == source and finding.get("matched") == "password"
                for finding in data.get("findings", [])
            )
            observations.append(
                MemoryObservation(
                    phase=phase,
                    source=source,
                    inspected=True,
                    matched=True,
                    confidence="high" if source != "dom_text" else "medium",
                    matched_type=("password" if any(
                        f.get("source") == source and f.get("matched") == "password"
                        for f in data.get("findings", [])
                    ) else "username"),
                    location=paths[0] if paths else "",
                    evidence=[
                        f"redacted credential probe matched in {source}; occurrences are intentionally not reported",
                        f"password_probe_fingerprint={secret_fingerprint(probe.password)}" if matched_password else "username_probe_match_only",
                    ],
                )
            )
    return observations


def _scan_web_storage(page, probe: MemoryProbe, *, phase: str, kind: str) -> MemoryObservation:
    script = r"""
    (kind, username, password) => {
      const storage = kind === 'local' ? window.localStorage : window.sessionStorage;
      const findings = [];
      for (let i = 0; i < storage.length; i++) {
        const key = storage.key(i) || '';
        let value = '';
        try { value = String(storage.getItem(key) || ''); } catch (_) {}
        if (value.includes(password) || key.includes(password)) findings.push({key, matched:'password'});
        else if (value.includes(username) || key.includes(username)) findings.push({key, matched:'username'});
      }
      return findings;
    }
    """
    try:
        findings = page.evaluate(script, kind, probe.username, probe.password)
    except Exception as exc:
        return MemoryObservation(
            phase=phase,
            source=f"{kind}_storage",
            inspected=False,
            error=f"{type(exc).__name__}: {exc}",
        )
    if findings:
        return MemoryObservation(
            phase=phase,
            source=f"{kind}_storage",
            inspected=True,
            matched=True,
            confidence="high",
            evidence=[
                f"credential probe found in {kind}Storage; keys/values are redacted",
                f"password_probe_fingerprint={secret_fingerprint(probe.password)}",
            ],
        )
    return MemoryObservation(
        phase=phase,
        source=f"{kind}_storage",
        inspected=True,
        matched=False,
        confidence="high",
        evidence=[f"{kind}Storage inspected; no supplied credential probe was found"],
    )


def _scan_cookies(context, probe: MemoryProbe, *, phase: str) -> MemoryObservation:
    try:
        cookies = context.cookies()
    except Exception as exc:
        return MemoryObservation(
            phase=phase,
            source="cookies",
            inspected=False,
            error=f"{type(exc).__name__}: {exc}",
        )

    for cookie in cookies:
        name = str(cookie.get("name") or "")
        value = str(cookie.get("value") or "")
        if probe.password in value or probe.password in name:
            return MemoryObservation(
                phase=phase,
                source="cookies",
                inspected=True,
                matched=True,
                confidence="high",
                matched_type="password",
                location=name,
                evidence=[
                    "the exact supplied password probe appears in a browser cookie; cookie values are never emitted",
                    f"password_probe_fingerprint={secret_fingerprint(probe.password)}",
                ],
            )
        if probe.username in value or probe.username in name:
            return MemoryObservation(
                phase=phase,
                source="cookies",
                inspected=True,
                matched=True,
                confidence="medium",
                matched_type="username",
                location=name,
                evidence=["the supplied username probe appears in a browser cookie; cookie values are never emitted"],
            )

    return MemoryObservation(
        phase=phase,
        source="cookies",
        inspected=True,
        matched=False,
        confidence="high",
        evidence=["browser context cookies inspected; supplied credential probes were not found"],
    )


def _scan_indexeddb(page, probe: MemoryProbe, cfg: BrowserMemoryConfig, *, phase: str) -> MemoryObservation:
    script = r"""
    async ({username, password, maxDatabases, maxStores, maxRecords}) => {
      if (!('indexedDB' in window)) return {supported:false, findings:[], reason:'indexedDB_unavailable'};
      if (typeof indexedDB.databases !== 'function') return {supported:false, findings:[], reason:'databases_api_unavailable'};
      const dbs = await indexedDB.databases();
      const findings = [];
      const limitedDbs = dbs.slice(0, maxDatabases);

      const findInValue = (value, depth=0) => {
        if (depth > 3) return false;
        if (typeof value === 'string') return value.includes(password) || value.includes(username);
        if (!value || typeof value !== 'object') return false;
        try {
          for (const key of Object.keys(value).slice(0, 60)) {
            if (findInValue(value[key], depth + 1)) return true;
          }
        } catch (_) {}
        return false;
      };

      for (const meta of limitedDbs) {
        if (!meta.name) continue;
        const db = await new Promise((resolve, reject) => {
          const req = indexedDB.open(meta.name, meta.version);
          req.onerror = () => reject(req.error || new Error('open_failed'));
          req.onsuccess = () => resolve(req.result);
        }).catch(() => null);
        if (!db) continue;
        try {
          const storeNames = Array.from(db.objectStoreNames).slice(0, maxStores);
          for (const storeName of storeNames) {
            const matched = await new Promise((resolve) => {
              let count = 0;
              let done = false;
              try {
                const tx = db.transaction(storeName, 'readonly');
                const store = tx.objectStore(storeName);
                const req = store.openCursor();
                req.onerror = () => resolve(false);
                req.onsuccess = (event) => {
                  if (done) return;
                  const cursor = event.target.result;
                  if (!cursor || count >= maxRecords) { done = true; resolve(false); return; }
                  count += 1;
                  if (findInValue(cursor.value) || String(cursor.key ?? '').includes(password) || String(cursor.key ?? '').includes(username)) {
                    done = true; resolve(true); return;
                  }
                  cursor.continue();
                };
              } catch (_) { resolve(false); }
            });
            if (matched) findings.push({db: meta.name, store: storeName});
            if (findings.length >= 10) break;
          }
        } finally {
          try { db.close(); } catch (_) {}
        }
        if (findings.length >= 10) break;
      }
      return {supported:true, findings, databaseCount:dbs.length};
    }
    """
    try:
        result = page.evaluate(
            script,
            {
                "username": probe.username,
                "password": probe.password,
                "maxDatabases": cfg.indexeddb_max_databases,
                "maxStores": cfg.indexeddb_max_object_stores,
                "maxRecords": cfg.indexeddb_max_records_per_store,
            },
        )
    except Exception as exc:
        return MemoryObservation(
            phase=phase,
            source="indexeddb",
            inspected=False,
            error=f"{type(exc).__name__}: {exc}",
        )

    if not result.get("supported"):
        return MemoryObservation(
            phase=phase,
            source="indexeddb",
            inspected=False,
            matched=False,
            confidence="none",
            evidence=[f"IndexedDB audit unavailable: {result.get('reason', 'unknown')}"],
        )
    if result.get("findings"):
        return MemoryObservation(
            phase=phase,
            source="indexeddb",
            inspected=True,
            matched=True,
            confidence="high",
            location=str(result["findings"][0].get("db") or "") + "/" + str(result["findings"][0].get("store") or ""),
            evidence=[
                "credential probe found in bounded IndexedDB inspection; record contents are never emitted",
                f"password_probe_fingerprint={secret_fingerprint(probe.password)}",
            ],
        )
    return MemoryObservation(
        phase=phase,
        source="indexeddb",
        inspected=True,
        matched=False,
        confidence="high",
        evidence=[f"bounded IndexedDB inspection completed; databases_seen={result.get('databaseCount', 0)}"],
    )


def _scan_heap(page, probe: MemoryProbe, cfg: BrowserMemoryConfig, *, phase: str) -> tuple[MemoryObservation, bool, bool]:
    try:
        cdp = page.context.new_cdp_session(page)
    except Exception as exc:
        return (
            MemoryObservation(
                phase=phase,
                source="js_heap_snapshot",
                inspected=False,
                error=f"{type(exc).__name__}: {exc}",
            ),
            False,
            False,
        )

    try:
        try:
            cdp.send("HeapProfiler.collectGarbage")
        except Exception:
            pass
        result = scan_heap_snapshot_for_markers(
            cdp,
            username=probe.username,
            password=probe.password,
            max_bytes=cfg.heap_snapshot_max_bytes,
            overlap_bytes=cfg.heap_scan_overlap_bytes,
        )
        obs = MemoryObservation(
            phase=phase,
            source="js_heap_snapshot",
            inspected=result.examined,
            matched=result.matched_password,
            confidence="high" if result.matched_password else "medium",
            evidence=[
                "heap snapshot contents were scanned only for the supplied redacted probes; raw snapshot data is discarded",
                f"bytes_observed={result.bytes_observed}",
            ],
            error=result.error,
        )
        if result.truncated:
            obs.evidence.append("heap snapshot exceeded configured byte budget; scan is partial")
        if result.matched_password:
            obs.evidence.append(f"password_probe_fingerprint={secret_fingerprint(probe.password)}")
        return obs, result.supported, result.matched_password
    finally:
        try:
            cdp.detach()
        except Exception:
            pass


def _submit_login(page, user, pwd, *, cfg: BrowserMemoryConfig, login_url: str) -> bool:
    # Use the form's own submission behavior. Never fabricate an API request.
    try:
        form = pwd.locator("xpath=ancestor::form[1]").first
        if form.count() > 0:
            form.locator('button[type="submit"], input[type="submit"], button').first.click(timeout=1500)
        else:
            pwd.press("Enter")
    except Exception:
        try:
            pwd.press("Enter")
        except Exception:
            return False

    try:
        page.wait_for_timeout(cfg.post_submit_settle_ms)
    except Exception:
        pass

    current_url = page.url
    if not _looks_login_url(current_url, login_url):
        return True

    # A visible logout control is another common confirmation signal.
    try:
        logout = page.locator(
            'a[href*="logout" i], button:has-text("logout"), button:has-text("sign out"), a:has-text("sign out")'
        ).first
        if logout.count() > 0 and logout.is_visible():
            return True
    except Exception:
        pass

    # Treat a non-empty auth cookie as supporting evidence, but do not make it
    # the sole criterion unless a session cookie exists and the page changed.
    return False


def _logout(page, context, *, cfg: BrowserMemoryConfig, login_url: str) -> bool:
    try:
        logout = page.locator(
            'a[href*="logout" i], button:has-text("logout"), button:has-text("sign out"), a:has-text("sign out")'
        ).first
        if logout.count() > 0 and logout.is_visible():
            logout.click(timeout=1500)
            page.wait_for_timeout(cfg.post_submit_settle_ms)
            return True
    except Exception:
        pass

    for path in cfg.logout_paths:
        url = _absolute(login_url, path)
        if not _same_origin(login_url, url):
            continue
        try:
            page.goto(url, wait_until="domcontentloaded", timeout=cfg.timeout_ms)
            return True
        except Exception:
            continue
    return False


def run_browser_memory_assessment(
    target: str,
    *,
    probe: MemoryProbe,
    config: BrowserMemoryConfig,
    progress=None,
) -> BrowserRun:
    run = BrowserRun()
    if sync_playwright is None:
        run.errors.append("Playwright is not installed")
        return run

    from authentication.auth_discovery import login_page_candidates
    login_url = _absolute(target, config.login_path)
    candidate_urls = login_page_candidates(target, config.login_path) or [login_url]

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            context = browser.new_context(ignore_https_errors=not config.verify_tls)
            page = context.new_page()

            if progress:
                progress("Opening login page for browser-memory assessment")

            opened = False
            for candidate in candidate_urls:
                try:
                    page.goto(candidate, wait_until="domcontentloaded", timeout=config.timeout_ms)
                    page.wait_for_timeout(config.page_settle_ms)
                    if _find_password_locator(page) is not None:
                        login_url = candidate
                        opened = True
                        break
                except Exception:
                    continue
            if not opened:
                page.goto(login_url, wait_until="domcontentloaded", timeout=config.timeout_ms)
                page.wait_for_timeout(config.page_settle_ms)

            user, pwd = _fill_without_persisting_autofill(page, probe.username, probe.password)
            run.evidence.append("A unique synthetic probe was inserted into the login controls; the actual authorized password was not required for the transient-memory lane.")

            # Control sample: while the value is intentionally present, the probe
            # should be observable. This prevents a false negative caused by a
            # page failing to accept the value.
            control_obs = _scan_dom_and_reachable_globals(
                page,
                probe,
                config,
                phase="filled_control",
                include_globals=config.inspect_js_reachability,
            )
            run.observations.extend(control_obs)
            if not any(item.matched for item in control_obs):
                run.evidence.append("Filled-control probe was not observable through the browser DOM/JS scan; transient-memory conclusions are limited.")

            # Core TC07 condition: clear the field before any successful login and
            # test whether the page still retains the supplied password.
            try:
                pwd.fill("")
                if user is not None:
                    user.fill("")
            except Exception:
                pass
            page.wait_for_timeout(config.post_clear_settle_ms)

            cleared_obs = _scan_dom_and_reachable_globals(
                page,
                probe,
                config,
                phase="after_clear",
                include_globals=config.inspect_js_reachability,
            )
            run.observations.extend(cleared_obs)
            if any(item.matched and item.matched_type == "password" for item in cleared_obs):
                run.direct_issue = True

            if config.use_heap_snapshot:
                if progress:
                    progress("Taking bounded Chromium JS heap snapshot")
                heap_obs, supported, heap_issue = _scan_heap(
                    page,
                    probe,
                    config,
                    phase="after_clear_heap",
                )
                run.observations.append(heap_obs)
                run.heap_supported = supported
                run.heap_examined = heap_obs.inspected
                if heap_issue:
                    run.heap_issue = True

            # Storage/cookie audits are run after clear, but they are only findings
            # when the exact supplied probe is present, not merely because a token exists.
            if config.inspect_local_storage:
                obs = _scan_web_storage(page, probe, phase="after_clear", kind="local")
                run.observations.append(obs)
                run.storage_issue = run.storage_issue or (obs.matched and obs.matched_type == "password")
            if config.inspect_session_storage:
                obs = _scan_web_storage(page, probe, phase="after_clear", kind="session")
                run.observations.append(obs)
                run.storage_issue = run.storage_issue or (obs.matched and obs.matched_type == "password")
            if config.inspect_indexeddb:
                obs = _scan_indexeddb(page, probe, config, phase="after_clear")
                run.observations.append(obs)
                run.storage_issue = run.storage_issue or (obs.matched and obs.matched_type == "password")
            if config.inspect_cookies:
                obs = _scan_cookies(context, probe, phase="after_clear")
                run.observations.append(obs)
                run.storage_issue = run.storage_issue or (obs.matched and obs.matched_type == "password")

            # Authenticated lane: when operator-supplied credentials are available,
            # scan for the real password only in-memory and never emit its value.
            # The exact value is used only as a local probe; the report receives a
            # one-way fingerprint.
            if config.perform_authenticated_lane and config.authorized_username and config.authorized_password:
                if progress:
                    progress("Running authenticated memory-retention lane")
                page.close()
                context.close()
                context = browser.new_context(ignore_https_errors=not config.verify_tls)
                page = context.new_page()
                page.goto(login_url, wait_until="domcontentloaded", timeout=config.timeout_ms)
                page.wait_for_timeout(config.page_settle_ms)

                user, pwd = _fill_without_persisting_autofill(
                    page,
                    config.authorized_username,
                    config.authorized_password,
                )
                authenticated = _submit_login(page, user, pwd, cfg=config, login_url=login_url)
                run.authenticated = authenticated

                if authenticated:
                    real_probe = MemoryProbe(
                        username=config.authorized_username,
                        password=config.authorized_password,
                    )
                    # Clear the credential field first; retention after this point
                    # is the security-relevant condition.
                    try:
                        pwd.fill("")
                    except Exception:
                        pass
                    page.wait_for_timeout(config.post_clear_settle_ms)

                    auth_obs = _scan_dom_and_reachable_globals(
                        page,
                        real_probe,
                        config,
                        phase="authenticated_after_clear",
                        include_globals=config.inspect_js_reachability,
                    )
                    run.observations.extend(auth_obs)
                    if any(item.matched and item.matched_type == "password" for item in auth_obs):
                        run.direct_issue = True

                    if config.inspect_local_storage:
                        obs = _scan_web_storage(page, real_probe, phase="authenticated_after_clear", kind="local")
                        run.observations.append(obs)
                        run.storage_issue = run.storage_issue or (obs.matched and obs.matched_type == "password")
                    if config.inspect_session_storage:
                        obs = _scan_web_storage(page, real_probe, phase="authenticated_after_clear", kind="session")
                        run.observations.append(obs)
                        run.storage_issue = run.storage_issue or (obs.matched and obs.matched_type == "password")
                    if config.inspect_indexeddb:
                        obs = _scan_indexeddb(page, real_probe, config, phase="authenticated_after_clear")
                        run.observations.append(obs)
                        run.storage_issue = run.storage_issue or (obs.matched and obs.matched_type == "password")
                    if config.inspect_cookies:
                        obs = _scan_cookies(context, real_probe, phase="authenticated_after_clear")
                        run.observations.append(obs)
                        run.storage_issue = run.storage_issue or (obs.matched and obs.matched_type == "password")

                    if config.use_heap_snapshot:
                        heap_obs, supported, heap_issue = _scan_heap(
                            page,
                            real_probe,
                            config,
                            phase="authenticated_after_clear_heap",
                        )
                        run.observations.append(heap_obs)
                        run.heap_supported = run.heap_supported or supported
                        run.heap_examined = run.heap_examined or heap_obs.inspected
                        run.heap_issue = run.heap_issue or heap_issue

                    if config.logout_after_authenticated_lane:
                        _logout(page, context, cfg=config, login_url=login_url)
                        page.wait_for_timeout(config.post_clear_settle_ms)

                        logout_obs = _scan_dom_and_reachable_globals(
                            page,
                            real_probe,
                            config,
                            phase="after_logout",
                            include_globals=config.inspect_js_reachability,
                        )
                        run.observations.extend(logout_obs)
                        if any(item.matched and item.matched_type == "password" for item in logout_obs):
                            run.direct_issue = True

                        if config.inspect_local_storage:
                            obs = _scan_web_storage(page, real_probe, phase="after_logout", kind="local")
                            run.observations.append(obs)
                            run.storage_issue = run.storage_issue or (obs.matched and obs.matched_type == "password")
                        if config.inspect_session_storage:
                            obs = _scan_web_storage(page, real_probe, phase="after_logout", kind="session")
                            run.observations.append(obs)
                            run.storage_issue = run.storage_issue or (obs.matched and obs.matched_type == "password")
                        if config.inspect_indexeddb:
                            obs = _scan_indexeddb(page, real_probe, config, phase="after_logout")
                            run.observations.append(obs)
                            run.storage_issue = run.storage_issue or (obs.matched and obs.matched_type == "password")
                        if config.inspect_cookies:
                            obs = _scan_cookies(context, real_probe, phase="after_logout")
                            run.observations.append(obs)
                            run.storage_issue = run.storage_issue or (obs.matched and obs.matched_type == "password")

                        if config.use_heap_snapshot:
                            heap_obs, supported, heap_issue = _scan_heap(
                                page,
                                real_probe,
                                config,
                                phase="after_logout_heap",
                            )
                            run.observations.append(heap_obs)
                            run.heap_supported = run.heap_supported or supported
                            run.heap_examined = run.heap_examined or heap_obs.inspected
                            run.heap_issue = run.heap_issue or heap_issue
                else:
                    run.errors.append(
                        "authorized credentials were supplied, but the browser could not independently confirm a successful authenticated state"
                    )

            browser.close()

    except PlaywrightTimeoutError as exc:
        run.errors.append(f"Playwright timeout: {exc}")
    except Exception as exc:
        run.errors.append(f"{type(exc).__name__}: {exc}")

    return run
