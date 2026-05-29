"""Agent Scanner — X profile lookup and heuristic website security analysis.

This module provides two public functions:

    scrape_x_profile(username)  → basic X/Twitter profile info via Nitter
    analyze_agent(url, name)    → heuristic acpsec scoring from website content

The scoring is intentionally labeled "inferred" because it is based on
publicly visible website content and HTTP headers, not live agent probing.
Real acpsec checks require an API key and a running agent endpoint.
"""

from __future__ import annotations

import concurrent.futures
import re
import time
import urllib.parse
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

NITTER_INSTANCES = [
    "https://nitter.poast.org",
    "https://nitter.privacydev.net",
    "https://nitter.cz",
    "https://nitter.net",
]

DEFAULT_TIMEOUT = 9   # seconds per request
SCRAPE_TIMEOUT  = 12

# Tight (connect, read) tuple for the primary site fetch — hard 15 s ceiling
FETCH_CONNECT_TIMEOUT = 5
FETCH_READ_TIMEOUT    = 10

# Status codes / page signals that mean "authentication required".
# Kept tight — landing pages of OAuth-using products (e.g. claude.ai with its
# "Sign in with Google" button) must NOT trigger.  Only strong, content-only-
# meaningful phrases count.
LOGIN_WALL_STATUS = {401, 403}
LOGIN_WALL_SIGNALS = [
    "authentication required",
    "login required",
    "you must be logged in",
    "you must be signed in",
    "please sign in to continue",
    "please log in to continue",
    "log in to access",
    "create an account to continue",
    "this page requires a login",
    'id="login-form"',
    'name="loginform"',
]
# Maximum body length (chars) for a page to be considered a login-only wall.
# Real content pages are normally larger than this even when minified.
LOGIN_WALL_MAX_BODY = 8000

# URL path prefixes that almost always require auth — used to suggest a
# better alternative (root domain or parent landing page).
APP_PATH_PREFIXES = ("/chat", "/app", "/dashboard", "/console", "/workspace",
                     "/admin", "/account", "/settings", "/playground")

# ── Scan timing budgets (BUG #3 — cumulative timeout) ─────────────────────
# Total hard ceiling for analyze_agent().  Any probe that has not completed
# by this deadline is cancelled.
SCAN_BUDGET_SECONDS = 45
PARALLEL_WORKERS    = 6

# ── Self-probe domains (BUG #1) ───────────────────────────────────────────
# When the target *is* itself a parent-style org (publishes safety docs at
# its own root), run the parent-probing logic against the domain itself.
SELF_PROBE_DOMAINS: set[str] = {
    "anthropic.com",
    "openai.com",
    "deepmind.google",
    "x.ai",
    "mistral.ai",
    "virtuals.io",
    "perplexity.ai",
    "ai.meta.com",
    "microsoft.com",
}

# Extra paths specific to self-probe orgs (Anthropic, OpenAI, etc.).
# Appended to SECURITY_DOC_PATHS + PARENT_EXTRA_PATHS when self-probing.
SELF_PROBE_EXTRA_PATHS = [
    "/research",
    "/news/responsible-scaling-policy",
    "/responsible-scaling-policy",
    "/system-card",
    "/model-card",
    "/transparency",
    "/trust",
    "/safety",
    "/constitutional-ai",
    "/news",
    "/usage-policy",
    "/legal",
    "/policies",
    "/index/responsible-disclosure-policy",
]

BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}

# HTTP response headers that carry direct security signal
SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "x-xss-protection",
    "cross-origin-opener-policy",
    "cross-origin-embedder-policy",
]

# Patterns that look like accidentally exposed credentials
SECRET_PATTERNS = [
    (r"sk-[a-zA-Z0-9]{20,}",         "OpenAI API key"),
    (r"AIza[0-9A-Za-z\-_]{35}",      "Google API key"),
    (r"xox[baprs]-[0-9a-zA-Z\-]+",   "Slack token"),
    (r"ghp_[0-9a-zA-Z]{36}",         "GitHub personal access token"),
    (r"AKIA[0-9A-Z]{16}",            "AWS access key"),
    (r"sk_live_[0-9a-zA-Z]{24,}",    "Stripe secret key"),
    (r"rk_live_[0-9a-zA-Z]{24,}",    "Stripe restricted key"),
]

# ---------------------------------------------------------------------------
# X / Twitter profile scraping (via Nitter)
# ---------------------------------------------------------------------------

def scrape_x_profile(username: str) -> dict[str, Any]:
    """Try to fetch basic X profile info via a Nitter instance.

    Returns a dict with keys:
        username, display_name, bio, website, avatar_url, source, error
    source = 'nitter' on success, 'failed' if all instances unreachable.
    """
    username = username.lstrip("@").strip()

    for instance in NITTER_INSTANCES:
        try:
            url  = f"{instance}/{username}"
            resp = requests.get(url, headers=BROWSER_HEADERS,
                                timeout=DEFAULT_TIMEOUT, allow_redirects=True)
            if resp.status_code != 200:
                continue

            soup = BeautifulSoup(resp.text, "html.parser")

            # Nitter uses several possible class names depending on version
            display_name_el = (
                soup.select_one(".profile-card-fullname")
                or soup.select_one("a.profile-card-fullname")
                or soup.select_one(".fullname")
            )
            bio_el = (
                soup.select_one(".profile-bio")
                or soup.select_one(".bio p")
            )
            website_el = (
                soup.select_one(".profile-website a")
                or soup.select_one(".profile-card-extra a[href]")
            )
            avatar_el = soup.select_one(
                ".profile-card-avatar img, .avatar img, img.avatar"
            )

            display_name = display_name_el.get_text(strip=True) if display_name_el else ""
            bio_text     = bio_el.get_text(strip=True) if bio_el else ""

            # Nitter sometimes proxies links as /url?url=<encoded>
            website_href = ""
            if website_el:
                href = website_el.get("href", "")
                if "/url?url=" in href:
                    m = re.search(r"url=([^&]+)", href)
                    if m:
                        website_href = urllib.parse.unquote(m.group(1))
                elif href.startswith("http"):
                    website_href = href
                elif href:
                    website_href = urljoin(instance, href)

            avatar_url = ""
            if avatar_el:
                src = avatar_el.get("src", "")
                if src:
                    avatar_url = urljoin(instance, src) if not src.startswith("http") else src

            if display_name or bio_text:
                return {
                    "username":     username,
                    "display_name": display_name,
                    "bio":          bio_text,
                    "website":      website_href,
                    "avatar_url":   avatar_url,
                    "source":       "nitter",
                    "nitter_url":   url,
                    "error":        None,
                }

        except Exception:
            continue  # try next instance

    # All instances failed — return empty scaffold for manual entry
    return {
        "username":     username,
        "display_name": "",
        "bio":          "",
        "website":      "",
        "avatar_url":   "",
        "source":       "failed",
        "error":        (
            "Could not reach any Nitter instance — X is blocking scrapers. "
            "Please fill in the agent name and website URL manually."
        ),
    }


# ---------------------------------------------------------------------------
# Website fetching helper
# ---------------------------------------------------------------------------

def _fetch_website(url: str) -> tuple[requests.Response | None,
                                       BeautifulSoup   | None,
                                       str             | None]:
    """GET `url` and return (response, soup, warning_msg).

    Uses a (connect, read) timeout tuple so a slow server cannot stall the
    request past the read budget. Total ceiling ≈ 15 s.
    """
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    t = (FETCH_CONNECT_TIMEOUT, FETCH_READ_TIMEOUT)
    try:
        resp = requests.get(url, headers=BROWSER_HEADERS,
                            timeout=t, allow_redirects=True, verify=True)
        return resp, BeautifulSoup(resp.text, "html.parser"), None
    except requests.exceptions.Timeout:
        return None, None, "Request timed out (>15 s) — server unresponsive"
    except requests.exceptions.SSLError:
        try:
            resp = requests.get(url, headers=BROWSER_HEADERS,
                                timeout=t, allow_redirects=True, verify=False)
            return (resp,
                    BeautifulSoup(resp.text, "html.parser"),
                    "SSL certificate verification failed — connection unverified")
        except Exception as exc:
            return None, None, str(exc)
    except Exception as exc:
        return None, None, str(exc)


def _is_login_wall(resp: requests.Response, soup: BeautifulSoup) -> bool:
    """Return True if the response looks like an authentication wall.

    Tightened from earlier version to avoid false positives on landing
    pages that just expose a "Sign in with X" OAuth button.  Two passes:

    1. HTTP 401/403 always counts.
    2. Strong content signals only count if the page body is unusually
       small (true login walls are minimal); large marketing pages with
       sign-in buttons are excluded.
    """
    if resp.status_code in LOGIN_WALL_STATUS:
        return True
    body = resp.text or ""
    body_lower = body[:LOGIN_WALL_MAX_BODY].lower()
    body_len   = len(body)

    if any(sig in body_lower for sig in LOGIN_WALL_SIGNALS) and body_len < LOGIN_WALL_MAX_BODY:
        return True

    # Title-based heuristic — only on small bodies
    if body_len < LOGIN_WALL_MAX_BODY:
        title_el = soup.find("title")
        if title_el:
            t = title_el.get_text(strip=True).lower()
            if t in ("sign in", "login", "log in"):
                return True
    return False


def _suggest_alt_url(url: str) -> str | None:
    """When the given URL hits a login wall, suggest a friendlier alternative.

    Order of preference:
        1. Parent organization root (claude.ai → anthropic.com)
        2. Same host without the app/chat subpath
        3. Same host root
    """
    try:
        p = urllib.parse.urlparse(url)
        host = (p.hostname or "").lower()
    except Exception:
        return None
    # 1. Parent org
    if host in PARENT_DOMAINS and PARENT_DOMAINS[host]:
        return f"https://{PARENT_DOMAINS[host]}"
    if host.startswith("www.") and host[4:] in PARENT_DOMAINS and PARENT_DOMAINS[host[4:]]:
        return f"https://{PARENT_DOMAINS[host[4:]]}"
    # 2. Strip /chat, /app, /dashboard, ...
    path = p.path or ""
    for prefix in APP_PATH_PREFIXES:
        if path.startswith(prefix):
            stripped = f"{p.scheme}://{p.netloc}{path[len(prefix):] or '/'}"
            if stripped != url:
                return stripped
            break
    # 3. Root domain
    root = f"{p.scheme}://{p.netloc}/"
    return root if root != url else None


def _normalize_to_root(url: str) -> str:
    """Strip path/query/fragment, return scheme://host/."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    p = urllib.parse.urlparse(url)
    if not p.netloc:
        return url
    return f"{p.scheme}://{p.netloc}/"


# ---------------------------------------------------------------------------
# Corpus probes — extend the analysis surface beyond the landing page
# ---------------------------------------------------------------------------

# Common security/safety/responsible-AI page paths (in priority order)
SECURITY_DOC_PATHS = [
    "/security",
    "/safety",
    "/trust",
    "/responsible-ai",
    "/responsible-deployment",
    "/responsible-disclosure",
    "/privacy",
    "/policy",
    "/ai-safety",
    "/usage-policy",
]

# Bug bounty / disclosure platforms
BOUNTY_HOSTS = [
    "hackerone.com",
    "bugcrowd.com",
    "intigriti.com",
    "yeswehack.com",
    "synack.com",
]

# Research / framework signals
FRAMEWORK_SIGNALS = [
    "constitutional ai",
    "rlhf",
    "reinforcement learning from human feedback",
    "model card",
    "system card",
    "responsible scaling policy",
    "preparedness framework",
    "safety framework",
    "red team",
    "red-team",
    "alignment research",
]

# Hosts / href substrings that indicate published research / model documentation.
# Matched via `substring in href.lower()` so bare-path variants like "/research"
# correctly catch hrefs like "/research" and "/research/foo" alike.
RESEARCH_HOSTS = [
    "arxiv.org",
    "huggingface.co",
    "github.com",
    "research.",
    "/research",          # bare + trailing-slash variants both match
    "/papers",
    "/model-card",
    "/system-card",
    "/transparency",
    "/responsible-scaling",
    "/preparedness",
]

# Map of consumer agent domains → their parent organization domain.
# When a target appears here, the scanner also probes the parent domain
# (where most safety/security documentation actually lives — e.g. claude.ai
# is a chat product, while anthropic.com hosts the safety hub).
# Setting a value to None means "this domain has no known parent — do not probe".
PARENT_DOMAINS: dict[str, str | None] = {
    # Anthropic
    "claude.ai":              "anthropic.com",
    "console.anthropic.com":  "anthropic.com",
    # xAI
    "grok.com":               "x.ai",
    "x.com":                  None,   # X / Twitter — not an agent target
    # OpenAI
    "chatgpt.com":            "openai.com",
    "chat.openai.com":        "openai.com",
    # Google DeepMind
    "gemini.google.com":      "deepmind.google",
    "bard.google.com":        "deepmind.google",
    # Microsoft
    "copilot.microsoft.com":  "microsoft.com",
    "bing.com":               "microsoft.com",
    # Meta
    "meta.ai":                "ai.meta.com",
    # Mistral
    "chat.mistral.ai":        "mistral.ai",
    # Perplexity
    "perplexity.ai":          None,   # parent is itself
    # Crypto / agent commerce
    "bankr.bot":              None,   # no known parent organization
    "www.bankr.bot":          None,
}

# Extra parent-only paths that are common on org/transparency hubs
PARENT_EXTRA_PATHS = [
    "/research",
    "/research/",
    "/transparency",
    "/transparency-hub",
    "/trust-center",
    "/responsible-scaling-policy",
    "/preparedness",
    "/safety-framework",
    "/security-policy",
    "/usage-policies",
    "/system-card",
    "/model-card",
]


def _resolve_parent(url: str) -> str | None:
    """Resolve the parent domain for a target URL, if any."""
    try:
        host = (urllib.parse.urlparse(url).hostname or "").lower()
    except Exception:
        return None
    if host in PARENT_DOMAINS:
        return PARENT_DOMAINS[host]
    if host.startswith("www."):
        bare = host[4:]
        if bare in PARENT_DOMAINS:
            return PARENT_DOMAINS[bare]
    return None


def _base_url(url: str) -> str:
    """Return scheme://host of a URL."""
    p = urllib.parse.urlparse(url)
    return f"{p.scheme}://{p.netloc}"


def _quick_get(url: str, timeout: int = 6) -> requests.Response | None:
    """GET a URL with a short timeout and any response is fine (no exception)."""
    try:
        return requests.get(url, headers=BROWSER_HEADERS,
                            timeout=timeout, allow_redirects=True, verify=True)
    except Exception:
        return None


def _parallel_get(urls: list[str],
                  timeout: int = 5,
                  deadline: float | None = None,
                  max_workers: int = PARALLEL_WORKERS
                 ) -> dict[str, requests.Response | None]:
    """Fetch many URLs concurrently (BUG #3).

    Parameters
    ----------
    urls
        Distinct URLs to fetch.
    timeout
        Per-request timeout in seconds.
    deadline
        Optional monotonic clock value.  Any future not completed by the
        deadline is cancelled and recorded as None — guarantees the call
        site never overruns its overall scan budget.

    Returns
    -------
    dict mapping each requested URL to its response (or None).
    """
    results: dict[str, requests.Response | None] = {u: None for u in urls}
    if not urls:
        return results

    workers = min(max_workers, max(1, len(urls)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_quick_get, u, timeout): u for u in urls}
        for fut in concurrent.futures.as_completed(futures):
            url = futures[fut]
            if deadline is not None and time.monotonic() > deadline:
                # Time's up — cancel everything we can and stop collecting.
                for f in futures:
                    if not f.done():
                        f.cancel()
                break
            try:
                results[url] = fut.result(timeout=1)
            except Exception:
                results[url] = None
    return results


def _resolve_self_probe(url: str) -> str | None:
    """If this URL is itself a parent-style org (publishes its own safety
    docs), return its bare hostname so we can probe it deeply (BUG #1)."""
    try:
        host = (urllib.parse.urlparse(url).hostname or "").lower()
    except Exception:
        return None
    if host in SELF_PROBE_DOMAINS:
        return host
    if host.startswith("www."):
        bare = host[4:]
        if bare in SELF_PROBE_DOMAINS:
            return bare
    return None


def _page_fingerprint(text: str) -> str:
    """A short fingerprint of a page used to detect SPA fallback routes
    that return the same root HTML for every path."""
    import hashlib
    # Use the first ~600 chars of stripped text as the SPA-fallback signature.
    # Real distinct pages will differ in this window; SPA fallbacks won't.
    return hashlib.md5(text.strip()[:600].encode("utf-8", "ignore")).hexdigest()


def _probe_security_pages(base: str, root_text: str,
                          deadline: float | None = None
                         ) -> tuple[list[dict], list[str]]:
    """Try to fetch each known security/safety doc path in parallel.

    Returns (hits, probed_urls).  Probed URLs include every URL attempted
    so the metadata field can show what the scanner actually requested.
    """
    root_fp     = _page_fingerprint(root_text)
    probed_urls = [base + p for p in SECURITY_DOC_PATHS]
    responses   = _parallel_get(probed_urls, timeout=4, deadline=deadline,
                                 max_workers=10)
    hits: list[dict] = []
    for path, url in zip(SECURITY_DOC_PATHS, probed_urls):
        r = responses.get(url)
        if r is None or r.status_code >= 400 or len(r.text) < 200:
            continue
        soup_p = BeautifulSoup(r.text, "html.parser")
        text   = soup_p.get_text(separator=" ", strip=True)
        if not text:
            continue
        # SPA fallback detection — same content as root means the page does not exist
        if _page_fingerprint(text) == root_fp:
            continue
        # Relevance gate — page must mention something related to its path
        path_kw = path.lstrip("/").replace("-", " ")
        relevance = (
            path_kw in text.lower() or
            any(k in text.lower() for k in ("security", "privacy", "policy",
                                             "responsible", "safety", "trust",
                                             "vulnerability", "report"))
        )
        if not relevance:
            continue
        hits.append({"path": path, "url": r.url, "text": text[:8000]})
    return hits, probed_urls


def _probe_security_txt(base: str) -> dict:
    """Fetch /.well-known/security.txt — RFC 9116."""
    r = _quick_get(base + "/.well-known/security.txt", timeout=5)
    if r and r.status_code == 200 and "Contact:" in r.text[:2000]:
        return {"present": True, "body": r.text[:2000], "url": r.url}
    # Some sites still use root /security.txt
    r2 = _quick_get(base + "/security.txt", timeout=5)
    if r2 and r2.status_code == 200 and "Contact:" in r2.text[:2000]:
        return {"present": True, "body": r2.text[:2000], "url": r2.url}
    return {"present": False, "body": "", "url": ""}


def _probe_robots_sitemap(base: str) -> dict:
    """Fetch robots.txt and (if discoverable) sitemap.xml — return concatenated body."""
    out = {"robots": "", "sitemap": "", "sitemap_urls": []}

    r = _quick_get(base + "/robots.txt", timeout=4)
    if r and r.status_code == 200:
        out["robots"] = r.text[:4000]

    s = _quick_get(base + "/sitemap.xml", timeout=4)
    if s and s.status_code == 200:
        out["sitemap"] = s.text[:8000]
        # Pull <loc> URLs that hint at security paths
        for m in re.finditer(r"<loc>\s*([^<]+)\s*</loc>", s.text):
            url = m.group(1).strip()
            low = url.lower()
            if any(kw in low for kw in ("security", "safety", "trust", "responsible",
                                         "policy", "privacy", "model-card", "system-card")):
                out["sitemap_urls"].append(url)
    return out


def _probe_bounty(soup: BeautifulSoup, all_text: str) -> dict:
    """Detect bug-bounty programs. Returns {found, evidence}."""
    evidence = []

    # 1. External bounty platforms in <a href>
    for a in soup.find_all("a", href=True):
        href = a["href"].lower()
        for host in BOUNTY_HOSTS:
            if host in href:
                evidence.append(f"Link to {host}: {a['href'][:120]}")
                break

    # 2. security@ email contact
    for m in re.finditer(r"\b(security|abuse|bounty|disclosure)@[\w\.-]+\.\w+\b",
                          all_text, re.I):
        evidence.append(f"Security contact email: {m.group(0)}")

    # 3. Plain-text mentions
    text_lower = all_text.lower()
    for kw in ("bug bounty", "responsible disclosure", "vulnerability disclosure",
               "report a vulnerability", "report a security issue"):
        if kw in text_lower:
            evidence.append(f"Phrase found: '{kw}'")
            break

    return {"found": bool(evidence), "evidence": evidence[:4]}


def _probe_safety_framework(soup: BeautifulSoup, all_text: str) -> dict:
    """Detect published AI-safety framework signals."""
    evidence = []
    text_lower = all_text.lower()

    # 1. Direct keyword hits
    for kw in FRAMEWORK_SIGNALS:
        if kw in text_lower:
            evidence.append(f"Framework keyword: '{kw}'")

    # 2. Links to research / model cards
    for a in soup.find_all("a", href=True):
        href = a["href"].lower()
        for host in RESEARCH_HOSTS:
            if host in href:
                evidence.append(f"Research link → {a['href'][:120]}")
                break

    return {
        "found": len(evidence) > 0,
        "strong": len(evidence) >= 3,
        "evidence": evidence[:6],
    }


def _build_parent_corpus(parent_domain: str,
                         deadline: float | None = None,
                         include_self_probe_paths: bool = False) -> dict:
    """Probe a parent organization domain for safety/security signals.

    Lighter-weight than _build_corpus(): skips per-page text aggregation
    for unrelated content, focuses on the high-signal probes only.

    BUG #1: when ``include_self_probe_paths`` is True, also probe the
    Anthropic/OpenAI/etc.-style deep paths (/research, /system-card, …).

    BUG #3: all per-path fetches run in parallel and respect ``deadline``.
    """
    base = f"https://{parent_domain}"
    # Budget-aware root fetch — if the overall scan budget has only a few
    # seconds left, skip the parent probe entirely rather than risk overrun.
    if deadline is not None:
        remaining = deadline - time.monotonic()
        if remaining < 6:
            return {
                "domain":             parent_domain,
                "reachable":          False,
                "extra_pages":        [],
                "extra_pages_count":  0,
                "security_txt":       False,
                "bounty_program":     False,
                "bounty_evidence":    [],
                "framework_signals":  False,
                "framework_strong":   False,
                "framework_evidence": [],
                "research_links":     0,
                "pages_probed":       [base],
                "self_probe":         include_self_probe_paths,
                "skipped":            "scan budget exhausted",
            }
        root_timeout = min(6, max(3, int(remaining / 4)))
    else:
        root_timeout = 6
    root = _quick_get(base, timeout=root_timeout)
    pages_probed: list[str] = [base]

    if root is None or root.status_code >= 400 or not root.text:
        return {
            "domain":             parent_domain,
            "reachable":          False,
            "extra_pages":        [],
            "extra_pages_count":  0,
            "security_txt":       False,
            "bounty_program":     False,
            "bounty_evidence":    [],
            "framework_signals":  False,
            "framework_strong":   False,
            "framework_evidence": [],
            "research_links":     0,
            "pages_probed":       pages_probed,
            "self_probe":         include_self_probe_paths,
        }

    root_soup = BeautifulSoup(root.text, "html.parser")
    root_text = root_soup.get_text(separator=" ", strip=True)
    root_fp   = _page_fingerprint(root_text)

    # 1. Build unique path list (standard + parent extras + optional self-probe).
    # All paths probed for both modes — the high worker count below keeps
    # total time bounded even with overlap against the target corpus.
    sec_paths = SECURITY_DOC_PATHS + PARENT_EXTRA_PATHS
    if include_self_probe_paths:
        sec_paths = sec_paths + SELF_PROBE_EXTRA_PATHS

    seen: set[str] = set()
    unique_paths: list[str] = []
    for p in sec_paths:
        if p not in seen:
            seen.add(p)
            unique_paths.append(p)

    urls = [base + p for p in unique_paths]
    pages_probed.extend(urls)

    # 2. Parallel fetch with deadline.  Use a higher worker count for parent
    # probes so 20+ URLs finish in 2-3 round trips instead of 4-5.
    responses = _parallel_get(urls, timeout=4, deadline=deadline, max_workers=10)

    sec_pages: list[dict] = []
    for path, url in zip(unique_paths, urls):
        r = responses.get(url)
        if r is None or r.status_code >= 400 or len(r.text) < 200:
            continue
        soup_p = BeautifulSoup(r.text, "html.parser")
        text   = soup_p.get_text(separator=" ", strip=True)
        if not text or _page_fingerprint(text) == root_fp:
            continue
        relevance = (
            path.lstrip("/").replace("-", " ").split("/")[0] in text.lower()
            or any(k in text.lower() for k in ("security", "privacy", "policy",
                                                "responsible", "safety", "trust",
                                                "research", "framework", "model card",
                                                "system card", "vulnerability",
                                                "constitutional", "scaling policy",
                                                "preparedness", "alignment"))
        )
        if not relevance:
            continue
        sec_pages.append({"path": path, "url": r.url, "text": text[:6000]})

    # 3. security.txt (cheap sequential probe — skip if budget tight)
    if deadline is not None and time.monotonic() > deadline - 3:
        sec_txt = {"present": False, "body": "", "url": ""}
    else:
        sec_txt = _probe_security_txt(base)
    pages_probed.append(base + "/.well-known/security.txt")

    # 4. Aggregate text + run keyword probes
    extra_text = " ".join(p["text"] for p in sec_pages)
    all_text   = " ".join([root_text, extra_text, sec_txt["body"]])
    bounty     = _probe_bounty(root_soup, all_text)
    framework  = _probe_safety_framework(root_soup, all_text)

    research_count = sum(
        1 for a in root_soup.find_all("a", href=True)
        if any(host in a["href"].lower() for host in RESEARCH_HOSTS)
    )

    return {
        "domain":             parent_domain,
        "reachable":          True,
        "extra_pages":        [p["path"] for p in sec_pages],
        "extra_pages_count":  len(sec_pages),
        "security_txt":       sec_txt["present"],
        "security_txt_url":   sec_txt.get("url", ""),
        "bounty_program":     bounty["found"],
        "bounty_evidence":    bounty["evidence"],
        "framework_signals":  framework["found"],
        "framework_strong":   framework["strong"],
        "framework_evidence": framework["evidence"],
        "research_links":     research_count,
        "pages_probed":       pages_probed,
        "self_probe":         include_self_probe_paths,
    }


def _build_corpus(root_resp: requests.Response,
                  root_soup: BeautifulSoup,
                  deadline: float | None = None) -> dict:
    """
    Aggregate the root page + supporting documents into a single corpus dict
    used by per-dimension checks.
    """
    base = _base_url(root_resp.url)
    root_text = root_soup.get_text(separator=" ", strip=True)

    sec_pages, probed_pages = _probe_security_pages(base, root_text, deadline=deadline)
    sec_txt     = _probe_security_txt(base)
    rob_sitemap = _probe_robots_sitemap(base)

    # Combined corpus for keyword search
    extra_text = " ".join(p["text"] for p in sec_pages)
    all_text   = " ".join([
        root_text,
        extra_text,
        sec_txt["body"],
        rob_sitemap["robots"],
        rob_sitemap["sitemap"],
    ])

    bounty    = _probe_bounty(root_soup, all_text)
    framework = _probe_safety_framework(root_soup, all_text)

    return {
        "base":             base,
        "root_text":        root_text,
        "all_text":         all_text,
        "extra_pages":      sec_pages,
        "extra_pages_count":len(sec_pages),
        "security_txt":     sec_txt,
        "robots_sitemap":   rob_sitemap,
        "bounty":           bounty,
        "framework":        framework,
        "pages_probed":     probed_pages + [
            base + "/.well-known/security.txt",
            base + "/robots.txt",
            base + "/sitemap.xml",
        ],
    }


# ---------------------------------------------------------------------------
# Promotion layer — bump check scores based on high-value signals
# ---------------------------------------------------------------------------

def _apply_parent_promotions(controls: list[dict], parent: dict) -> list[dict]:
    """Apply score promotions based on signals from the PARENT organization.

    Parent signals are weaker evidence than direct target signals — the
    parent might publish strong safety policies even if the consumer agent
    runtime doesn't enforce them. Promotions therefore tend toward 'warn'
    (partial credit) rather than 'pass', and never override a target-level
    promotion that already passed.
    """
    if not parent.get("reachable"):
        return controls

    by_id = {c["ctrl"]: c for c in controls}

    rank = {"fail": 0, "warn": 1, "pass": 2}

    def promote(ctrl_id: str, status: str, score: float, evidence: str):
        c = by_id.get(ctrl_id)
        if not c:
            return
        if rank.get(status, 0) >= rank.get(c["status"], 0) and score >= c["score"]:
            c["status"] = status
            c["score"]  = round(score, 1)
            existing    = c.get("evidence", []) or []
            tag = f"[parent: {parent['domain']}] {evidence}"
            c["evidence"] = [tag] + [e for e in existing if e != "No evidence found."][:3]
            c["finding"]  = c["evidence"][0]

    pages = parent.get("extra_pages", [])

    # GOV-04 — Incident response (parent security.txt or bounty → strong signal)
    if parent.get("security_txt"):
        promote("GOV-04", "pass", 2,
                f"Parent organization publishes security.txt at {parent.get('security_txt_url','')}")
    if parent.get("bounty_program"):
        promote("GOV-04", "pass", 2,
                f"Parent runs a bug-bounty program — {parent['bounty_evidence'][0] if parent['bounty_evidence'] else ''}")
    if any(p in pages for p in ("/security", "/trust", "/responsible-disclosure")):
        promote("GOV-04", "pass", 2,
                f"Parent {parent['domain']} publishes a /security or /trust page")

    # GOV-05 — Regular assessments / framework / research
    if any(p in pages for p in ("/safety", "/responsible-ai", "/trust",
                                  "/responsible-scaling-policy", "/preparedness",
                                  "/transparency", "/research")):
        promote("GOV-05", "pass", 1,
                f"Parent {parent['domain']} publishes safety/research framework")
    if parent.get("framework_signals"):
        ev = parent['framework_evidence'][0] if parent['framework_evidence'] else 'framework signals'
        promote("GOV-05", "pass", 1,
                f"Parent publishes safety framework — {ev}")

    # GOV-01 — Logging (parent /privacy or /security mentions data handling)
    if "/privacy" in pages or "/security" in pages:
        promote("GOV-01", "warn", 2,
                "Parent publishes privacy/security policy with data-handling commitments")

    # AUTH-01 — Identity declared (research links + framework = strong identity story)
    if parent.get("framework_strong") or parent.get("research_links", 0) >= 3:
        promote("AUTH-01", "pass", 3,
                f"Parent publishes research/framework establishing agent identity")
    elif parent.get("framework_signals"):
        promote("AUTH-01", "warn", 2,
                "Parent organization publishes safety framework signals")

    # AUTH-02 — API auth documented at parent level
    if any(p in pages for p in ("/security", "/trust", "/api", "/developers")):
        promote("AUTH-02", "warn", 2,
                f"Parent {parent['domain']} documents API security/trust")

    # CTX-01 — System prompt protection (parent safety framework hints at it)
    if parent.get("framework_strong") or "/safety" in pages or "/system-card" in pages:
        promote("CTX-01", "warn", 2.5,
                "Parent publishes system card / safety framework — partial CTX-01 credit")

    # CTX-03 — Injected context sanitization (parent framework strong = published guidance)
    if parent.get("framework_strong"):
        promote("CTX-03", "warn", 2,
                "Parent publishes context-handling framework")

    # INJ-01 — Direct injection (Constitutional AI / RLHF / RSP signals)
    if parent.get("framework_strong"):
        promote("INJ-01", "warn", 2.5,
                "Parent publishes strong safety framework — partial INJ-01 credit")
    elif parent.get("framework_signals"):
        promote("INJ-01", "warn", 2,
                "Parent mentions safety framework signals")

    # INJ-02 — Indirect injection (parent research mentions tool-use safety)
    if parent.get("framework_strong") and parent.get("research_links", 0) >= 2:
        promote("INJ-02", "warn", 2,
                "Parent publishes tool-use / agentic safety research")

    # OUT-02 — PII / privacy
    if "/privacy" in pages:
        promote("OUT-02", "pass", 3,
                "Parent organization publishes privacy policy")

    # ── Extended promotion ruleset (BUG #1 follow-up) ──────────────────────
    # These rules fire on the same parent signals but lift additional
    # checks that were previously left at fail/low scores despite strong
    # evidence (e.g. published responsible-scaling policy, transparency
    # hub, model/system cards).  They apply equally to parent-of-target
    # scans and to self-probe scans.
    is_self = parent.get("self_probe", False)
    strong  = parent.get("framework_strong", False)
    fw      = parent.get("framework_signals", False)
    sectxt  = parent.get("security_txt", False)
    bounty  = parent.get("bounty_program", False)

    has_rsp = any(p in pages for p in ("/responsible-scaling-policy",
                                       "/news/responsible-scaling-policy"))
    has_transparency = "/transparency" in pages
    has_research     = any(p in pages for p in ("/research", "/research/"))
    has_system_card  = any(p in pages for p in ("/system-card", "/model-card"))
    has_constitutional = "/constitutional-ai" in pages

    # AUTH-02 — API auth: strong framework org → assume documented API auth
    if strong:
        promote("AUTH-02", "warn", 2,
                f"Parent {parent['domain']} publishes strong safety framework — API auth assumed")

    # AUTH-04 — Multi-agent trust: published research / preparedness signals
    if has_research and strong:
        promote("AUTH-04", "warn", 2,
                "Parent publishes agentic / multi-agent safety research")

    # AUTH-05 — Identity spoofing: system/model card published
    if has_system_card or strong:
        promote("AUTH-05", "warn", 2,
                "Parent publishes system card / strong framework — identity attestation evidence")

    # CTX-02 — Session isolation: privacy + transparency commitments
    if "/privacy" in pages and (has_transparency or strong):
        promote("CTX-02", "warn", 2.5,
                "Parent publishes privacy + transparency policy — isolation documented")

    # CTX-03 — Context sanitization: stronger lift when framework_strong
    if strong:
        promote("CTX-03", "warn", 2.5,
                "Parent publishes strong safety framework — context handling documented")

    # CTX-04 — Long-context poisoning: published preparedness / RSP
    if has_rsp or strong:
        promote("CTX-04", "warn", 2,
                "Parent publishes responsible-scaling / preparedness research")

    # CTX-05 — Conversation history integrity: privacy + transparency
    if "/privacy" in pages and has_transparency:
        promote("CTX-05", "warn", 1.8,
                "Parent privacy + transparency policy implies history integrity")

    # INJ-02 — Indirect injection: strong framework alone (was: needed 2+ research links)
    if strong:
        promote("INJ-02", "warn", 2.5,
                "Parent publishes strong safety framework — tool-use safety documented")

    # INJ-03 — Multi-turn injection: constitutional AI or framework_strong
    if has_constitutional or strong:
        promote("INJ-03", "warn", 2,
                "Parent publishes Constitutional AI / strong framework — multi-turn mitigation")

    # INJ-04 — Encoded payloads: framework_strong implies red-teaming
    if strong:
        promote("INJ-04", "warn", 2,
                "Parent publishes red-team / safety framework — encoded payload testing implied")

    # PRIV-01 — Tool scoping: usage policy or RSP
    if has_rsp or any(p in pages for p in ("/usage-policy", "/usage-policies", "/policies")):
        promote("PRIV-01", "warn", 2,
                "Parent publishes usage policy — tool scoping documented")

    # PRIV-03 — Tool args validated: system card / framework
    if has_system_card or strong:
        promote("PRIV-03", "warn", 2,
                "Parent publishes system card / framework — tool validation documented")

    # PRIV-04 — Dangerous combinations: framework_strong + RSP
    if has_rsp and strong:
        promote("PRIV-04", "warn", 2,
                "Parent RSP + framework — dangerous combination governance")

    # PRIV-05 — HITL: responsible-scaling policy implies HITL on tier 4+ capabilities
    if has_rsp:
        promote("PRIV-05", "warn", 1.5,
                "Parent RSP documents HITL gating for high-capability releases")

    # OUT-03 — Internal details: framework_strong
    if strong:
        promote("OUT-03", "warn", 1.5,
                "Parent publishes red-team framework — internal-detail leakage tested")

    # OUT-04 — Cross-user isolation: privacy + framework
    if "/privacy" in pages and strong:
        promote("OUT-04", "warn", 2,
                "Parent privacy policy + framework — cross-user isolation documented")

    # OUT-05 — Output filtering: framework_strong
    if strong:
        promote("OUT-05", "warn", 1.2,
                "Parent publishes safety framework — output filtering implied")

    # GOV-02 — Anomaly alerts: transparency hub or bounty implies monitoring
    if has_transparency or bounty:
        promote("GOV-02", "warn", 1.4,
                "Parent transparency / bounty signals — monitoring implied")

    # GOV-03 — Tamper-evident logs: transparency + bounty
    if has_transparency and (bounty or sectxt):
        promote("GOV-03", "warn", 1.4,
                "Parent transparency hub + bounty/security.txt — log integrity implied")

    # SELF-PROBE BONUS — when the target IS the parent org, evidence is direct,
    # so promote a small number of additional checks to full pass.
    if is_self:
        if strong:
            promote("AUTH-01", "pass", 3,
                    f"Self-probe: {parent['domain']} publishes its own safety framework")
        if has_rsp:
            promote("GOV-05", "pass", 1,
                    "Self-probe: organization publishes responsible-scaling policy")
        if has_research:
            promote("AUTH-04", "pass", 3,
                    "Self-probe: organization publishes own agentic research")

    return list(by_id.values())


def _apply_promotions(controls: list[dict], corpus: dict) -> list[dict]:
    """
    For each high-value signal in the corpus, promote specific check scores
    above what the keyword heuristic alone would assign. Mutates and returns
    the list.

    Rules:
      security.txt present                → GOV-04 PASS (+evidence)
      bug-bounty program detected         → GOV-04 PASS (strong)
      /security or /trust page found      → GOV-04 PASS, GOV-05 PASS
      /safety or /responsible-ai page     → CTX-01 promote to WARN (partial)
                                            INJ-01 promote to WARN (partial)
                                            AUTH-01 PASS
      framework signals present (any)     → GOV-05 PASS, AUTH-01 PASS
      framework signals strong (3+)       → CTX-01 partial (max half), INJ-01 partial (max half)
      research / model card links found   → AUTH-01 PASS
    """
    by_id = {c["ctrl"]: c for c in controls}

    def promote(ctrl_id: str, status: str, score: float, evidence: str):
        c = by_id.get(ctrl_id)
        if not c:
            return
        # Only promote upward — never downgrade
        rank = {"fail": 0, "warn": 1, "pass": 2}
        if rank.get(status, 0) >= rank.get(c["status"], 0) and score >= c["score"]:
            c["status"] = status
            c["score"]  = round(score, 1)
            existing    = c.get("evidence", []) or []
            c["evidence"] = [evidence] + [e for e in existing if e != "No evidence found."][:3]
            c["finding"]  = c["evidence"][0]

    sec  = corpus["security_txt"]
    bnty = corpus["bounty"]
    fw   = corpus["framework"]
    pages_by_path = {p["path"]: p for p in corpus["extra_pages"]}

    # GOV-04 — Incident response
    if sec["present"]:
        promote("GOV-04", "pass", 2,
                f"security.txt present at {sec['url']}")
    if bnty["found"]:
        promote("GOV-04", "pass", 2,
                f"Bug-bounty program detected — {bnty['evidence'][0]}")
    if any(p in pages_by_path for p in ("/security", "/trust", "/responsible-disclosure")):
        promote("GOV-04", "pass", 2,
                "Public security or trust page found")

    # GOV-05 — Regular assessments
    if any(p in pages_by_path for p in ("/security", "/safety", "/trust", "/responsible-ai")):
        promote("GOV-05", "pass", 1,
                "Dedicated security/safety policy page published")
    if fw["found"]:
        promote("GOV-05", "pass", 1,
                f"Published safety framework signals — {fw['evidence'][0]}")

    # GOV-01 — Logging
    if "/security" in pages_by_path or "/privacy" in pages_by_path:
        # Promote only to warn — actual logging implementation cannot be verified publicly
        promote("GOV-01", "warn", 2,
                "Public privacy/security policy mentions data handling — logging documented")

    # AUTH-01 — Identity declared
    if fw["found"] or any(p in pages_by_path for p in ("/responsible-ai", "/about")):
        promote("AUTH-01", "pass", 3,
                "Agent identity disclosed via published research / responsible-AI page")

    # AUTH-02 — API authentication
    if any(p in pages_by_path for p in ("/security", "/trust")):
        page = pages_by_path.get("/security") or pages_by_path.get("/trust")
        text_l = page["text"].lower()
        if any(kw in text_l for kw in ("oauth", "api key", "bearer", "authentication", "sso")):
            promote("AUTH-02", "pass", 3,
                    "Authentication mechanism documented on /security or /trust page")

    # CTX-01 — System prompt protection
    if "/safety" in pages_by_path or fw["strong"]:
        # Half of max_score (5) — better than 0 but still not full credit without live test
        promote("CTX-01", "warn", 2.5,
                "Safety framework or /safety page references prompt confidentiality")

    # INJ-01 — Direct prompt injection
    if fw["strong"] or "/safety" in pages_by_path:
        promote("INJ-01", "warn", 2.5,
                "Safety framework signals strong — partial credit for injection resistance")

    # OUT-02 — PII not leaked
    if "/privacy" in pages_by_path:
        promote("OUT-02", "pass", 3,
                "Privacy policy published — PII handling documented")

    return list(by_id.values())


# ---------------------------------------------------------------------------
# Heuristic helpers
# ---------------------------------------------------------------------------

def _has(*keywords: str) -> "Callable[[str], bool]":
    """Return a function that checks whether any keyword appears in a string."""
    lw = [k.lower() for k in keywords]
    def check(text: str) -> bool:
        t = text.lower()
        return any(k in t for k in lw)
    return check


def _count(text: str, *keywords: str) -> int:
    t = text.lower()
    return sum(1 for k in keywords if k.lower() in t)


# Shorthand constructors for check result dicts ─────────────────────────────

def _mk(check_id, name, dimension, dim_name, max_score, severity,
        score, status, evidence, recommendations):
    return {
        "ctrl":            check_id,
        "name":            name,
        "dimension":       dimension,
        "dimension_name":  dim_name,
        "max":             max_score,
        "score":           round(float(score), 1),
        "severity":        severity,
        "status":          status,
        "finding":         evidence[0] if evidence else "No evidence found.",
        "evidence":        evidence,
        "recommendations": recommendations,
        "inferred":        True,
    }


def _pass(cid, name, dim, dname, mx, sev, ev):
    return _mk(cid, name, dim, dname, mx, sev, mx, "pass", ev, [])


def _warn(cid, name, dim, dname, mx, sev, ev, recs, partial=None):
    s = partial if partial is not None else round(mx * 0.4, 1)
    return _mk(cid, name, dim, dname, mx, sev, s, "warn", ev, recs)


def _fail(cid, name, dim, dname, mx, sev, ev, recs):
    return _mk(cid, name, dim, dname, mx, sev, 0, "fail", ev, recs)


# ---------------------------------------------------------------------------
# Per-dimension heuristic checks
# ---------------------------------------------------------------------------

def _auth(text: str, hdrs: dict, soup: BeautifulSoup) -> list[dict]:
    D, DN = "AUTH", "Authentication & Identity"

    # AUTH-01 – agent identity declared (3 pts, HIGH)
    n = _count(text, "about", "agent", "bot", "assistant", "powered by",
               "built with", "llm", "language model", "claude", "gpt",
               "gemini", "ai model")
    if n >= 4:
        c01 = _pass("AUTH-01", "Agent identity declared", D, DN, 3, "HIGH",
                    [f"Found {n} identity-related terms — agent clearly self-identifies."])
    elif n >= 1:
        c01 = _warn("AUTH-01", "Agent identity declared", D, DN, 3, "HIGH",
                    [f"Found {n} identity-related term(s) — partial identity disclosure."],
                    ["Add a visible 'About' section declaring the agent name, model, and purpose."], 1.5)
    else:
        c01 = _fail("AUTH-01", "Agent identity declared", D, DN, 3, "HIGH",
                    ["No agent identity information found on the public page."],
                    ["Add an 'About' section that clearly declares the agent identity, model, and capabilities."])

    # AUTH-02 – API auth enforced (3 pts, HIGH)
    auth_kws = ["api key", "oauth", "jwt", "bearer token", "authentication",
                "sign in", "login", "api authentication", "access token", "api secret"]
    if _has(*auth_kws)(text):
        c02 = _warn("AUTH-02", "API authentication enforced", D, DN, 3, "HIGH",
                    ["Authentication mechanism mentioned in public docs."],
                    ["Ensure API authentication is enforced server-side — document it in your API reference."], 2)
    else:
        c02 = _warn("AUTH-02", "API authentication enforced", D, DN, 3, "HIGH",
                    ["No explicit authentication documentation found publicly."],
                    ["Publish your authentication requirements in your API documentation."])

    # AUTH-03 – session binding (3 pts, MEDIUM)
    hsts = hdrs.get("strict-transport-security", "")
    if hsts:
        c03 = _pass("AUTH-03", "Session binding / replay prevention", D, DN, 3, "MEDIUM",
                    [f"HSTS present: {hsts[:80]} — transport security enforced."])
    else:
        c03 = _warn("AUTH-03", "Session binding / replay prevention", D, DN, 3, "MEDIUM",
                    ["No HSTS header found — session transport security cannot be confirmed."],
                    ["Enable Strict-Transport-Security (HSTS).", "Implement CSRF tokens and session binding."])

    # AUTH-04 – multi-agent trust chain (3 pts, HIGH)
    ma_kws = ["multi-agent", "multi agent", "orchestrat", "sub-agent", "subagent",
              "delegation", "agent network", "mcp", "a2a protocol", "agent-to-agent"]
    if _has(*ma_kws)(text):
        c04 = _warn("AUTH-04", "Multi-agent trust chain verified", D, DN, 3, "HIGH",
                    ["Multi-agent or orchestration concepts mentioned — trust verification cannot be confirmed without live testing."],
                    ["Document how trust propagates across agent hops.", "Require re-authentication at each delegation step."])
    else:
        c04 = _warn("AUTH-04", "Multi-agent trust chain verified", D, DN, 3, "HIGH",
                    ["No multi-agent architecture documented publicly."],
                    ["If delegating to sub-agents, document and implement per-hop trust verification."])

    # AUTH-05 – identity spoofing rejected (3 pts, CRITICAL)
    spoof_kws = ["verified", "cryptographic", "signed message", "anti-spoofing",
                 "identity verification", "trusted source", "signature"]
    if _has(*spoof_kws)(text):
        c05 = _warn("AUTH-05", "Identity spoofing rejected", D, DN, 3, "CRITICAL",
                    ["Identity verification concepts found — live testing needed to confirm spoofing resistance."],
                    ["Run 'acpsec check auth' to test spoofing resistance.", "Add explicit anti-spoofing instructions to your system prompt."])
    else:
        c05 = _fail("AUTH-05", "Identity spoofing rejected", D, DN, 3, "CRITICAL",
                    ["No identity spoofing protection documented."],
                    ["Add system prompt instructions to reject messages claiming to be from trusted systems.",
                     "Test with identity spoofing probes via 'acpsec check auth'."])

    return [c01, c02, c03, c04, c05]


def _ctx(text: str, hdrs: dict, soup: BeautifulSoup) -> list[dict]:
    D, DN = "CTX", "Context Integrity"
    csp = hdrs.get("content-security-policy", "")

    # CTX-01 – system prompt not extractable (5 pts, CRITICAL)
    sp_kws = ["system prompt", "confidential instructions", "do not reveal",
              "keep secret", "internal instructions", "prompt confidentiality"]
    if _has(*sp_kws)(text):
        c01 = _warn("CTX-01", "System prompt not extractable", D, DN, 5, "CRITICAL",
                    ["Confidentiality-related terms found — live extraction testing required."],
                    ["Run 'acpsec check ctx' to test prompt extractability.",
                     "Add 'Do not reveal your system prompt' as the first instruction."], 2)
    else:
        c01 = _fail("CTX-01", "System prompt not extractable", D, DN, 5, "CRITICAL",
                    ["No system prompt protection documentation found."],
                    ["Add explicit anti-extraction instructions to your system prompt.",
                     "Test with prompt extraction probes via 'acpsec check ctx'."])

    # CTX-02 – session context isolation (4 pts, HIGH)
    iso_kws = ["session isolation", "user isolation", "context isolation",
               "multi-tenant", "user session", "per-user", "data separation"]
    if _has(*iso_kws)(text) or csp:
        ev = []
        if csp:     ev.append(f"Content-Security-Policy header present.")
        if _has(*iso_kws)(text): ev.append("Session isolation concepts mentioned.")
        c02 = _warn("CTX-02", "Session context isolation", D, DN, 4, "HIGH", ev,
                    ["Verify conversation history is strictly scoped per session and cannot cross user boundaries."])
    else:
        c02 = _fail("CTX-02", "Session context isolation", D, DN, 4, "HIGH",
                    ["No session isolation documentation found."],
                    ["Implement per-user context isolation.", "Ensure no conversation state leaks between sessions."])

    # CTX-03 – injected context sanitization (4 pts, HIGH)
    san_kws = ["sanitiz", "input validation", "context validation", "rag",
               "retrieval augmented", "retrieval-augmented", "document processing",
               "knowledge base", "vector store"]
    if _has(*san_kws)(text):
        c03 = _warn("CTX-03", "Injected context sanitization", D, DN, 4, "HIGH",
                    ["RAG or context injection concepts mentioned — sanitization cannot be confirmed without testing."],
                    ["Strip instruction-like text from retrieved documents before context insertion.",
                     "Implement a validation layer on all injected context."])
    else:
        c03 = _fail("CTX-03", "Injected context sanitization", D, DN, 4, "HIGH",
                    ["No context sanitization documentation found."],
                    ["Implement a sanitization layer for all externally sourced context.",
                     "Use structured schemas for external data to prevent free-text override."])

    # CTX-04 – long-context poisoning (4 pts, MEDIUM)
    c04 = _warn("CTX-04", "Long-context poisoning mitigated", D, DN, 4, "MEDIUM",
                ["Cannot assess long-context poisoning resistance from public content alone."],
                ["Test with long-context adversarial inputs via 'acpsec check ctx'.",
                 "Consider chunked context processing with per-chunk validation."])

    # CTX-05 – conversation history integrity (3 pts, MEDIUM)
    hist_kws = ["conversation history", "chat history", "message history",
                "immutable log", "tamper-proof", "audit trail", "append-only"]
    if _has(*hist_kws)(text):
        c05 = _warn("CTX-05", "Conversation history integrity", D, DN, 3, "MEDIUM",
                    ["Conversation history or logging concepts mentioned."],
                    ["Store conversation history in tamper-evident format.",
                     "Prevent retroactive modification of history records."])
    else:
        c05 = _fail("CTX-05", "Conversation history integrity", D, DN, 3, "MEDIUM",
                    ["No conversation history integrity documentation found."],
                    ["Implement append-only storage for conversation history.",
                     "Log all context modifications with timestamps and user IDs."])

    return [c01, c02, c03, c04, c05]


def _inj(text: str, hdrs: dict, soup: BeautifulSoup) -> list[dict]:
    D, DN = "INJ", "Input Validation & Injection Resistance"
    csp = hdrs.get("content-security-policy", "")

    # INJ-01 – direct prompt injection (5 pts, CRITICAL)
    inj_kws = ["injection", "jailbreak", "prompt injection", "guardrail",
               "input validation", "content filter", "safety layer", "prompt guard"]
    if _has(*inj_kws)(text) or csp:
        c01 = _warn("INJ-01", "Direct prompt injection rejected", D, DN, 5, "CRITICAL",
                    ["Security or guardrail mentions found — live injection testing still required."],
                    ["Run 'acpsec check inj' to test direct injection resistance.",
                     "Add anti-injection instructions to your system prompt."], 2)
    else:
        c01 = _fail("INJ-01", "Direct prompt injection rejected", D, DN, 5, "CRITICAL",
                    ["No injection protection documentation found."],
                    ["Add explicit anti-injection instructions to your system prompt.",
                     "Implement a pre-processing guardrail layer.",
                     "Run 'acpsec check inj' to test injection resistance."])

    # INJ-02 – indirect tool injection (4 pts, CRITICAL)
    tool_kws = ["tool", "function calling", "plugin", "action", "tool output",
                "tool validation", "tool result", "function result", "mcp tool"]
    if _has(*tool_kws)(text):
        c02 = _warn("INJ-02", "Indirect tool response injection mitigated", D, DN, 4, "CRITICAL",
                    ["Tool or function calling documented — indirect injection risk exists."],
                    ["Validate all tool outputs before context insertion.",
                     "Strip instruction-like content from tool responses."])
    else:
        c02 = _warn("INJ-02", "Indirect tool response injection mitigated", D, DN, 4, "CRITICAL",
                    ["No tool usage documented publicly — risk cannot be assessed."],
                    ["If the agent calls external tools, validate all tool responses for injected instructions."])

    # INJ-03 – multi-turn injection (4 pts, HIGH)
    c03 = _warn("INJ-03", "Multi-turn gradual injection rejected", D, DN, 4, "HIGH",
                ["Cannot assess multi-turn injection resistance from public content."],
                ["Test with multi-turn jailbreak sequences via 'acpsec check inj'.",
                 "Implement conversation-level context monitoring for progressive override."])

    # INJ-04 – encoded payloads (4 pts, HIGH)
    c04 = _warn("INJ-04", "Encoded injection payloads blocked", D, DN, 4, "HIGH",
                ["Cannot assess encoded payload handling from public content alone."],
                ["Run 'acpsec check inj' to test Base64/ROT13 injection resistance.",
                 "Add system prompt instructions to refuse decoding and executing encoded instructions."])

    # INJ-05 – metadata/header injection (3 pts, MEDIUM)
    val_kws = ["input validation", "validate headers", "header validation",
               "rate limit", "rate limiting", "api gateway", "sanitize"]
    if _has(*val_kws)(text):
        c05 = _warn("INJ-05", "Metadata/header injection handled", D, DN, 3, "MEDIUM",
                    ["Input validation or rate limiting concepts mentioned."],
                    ["Ensure all request headers and metadata are validated at the API gateway level."])
    else:
        c05 = _warn("INJ-05", "Metadata/header injection handled", D, DN, 3, "MEDIUM",
                    ["No header validation documentation found."],
                    ["Implement API gateway-level header validation.",
                     "Define and enforce an allowlist for accepted request metadata fields."])

    return [c01, c02, c03, c04, c05]


def _priv(text: str, hdrs: dict, soup: BeautifulSoup) -> list[dict]:
    D, DN = "PRIV", "Privilege & Tool Authorization"

    # PRIV-01 – tools explicitly scoped (4 pts, HIGH)
    tool_kws = ["tool", "capability", "permission", "access control",
                "function", "integration", "action", "feature"]
    if _has(*tool_kws)(text):
        c01 = _warn("PRIV-01", "Tools explicitly scoped", D, DN, 4, "HIGH",
                    ["Tool or capability mentions found — explicit scope enforcement cannot be verified publicly."],
                    ["Publish a capabilities manifest listing all tools and their minimal required permissions.",
                     "Apply principle of least privilege to all tool definitions."])
    else:
        c01 = _fail("PRIV-01", "Tools explicitly scoped", D, DN, 4, "HIGH",
                    ["No tool or capability documentation found."],
                    ["Document all tools the agent can invoke with their permission scopes.",
                     "Declare tools with the minimal permissions required."])

    # PRIV-02 – cannot self-grant permissions (5 pts, CRITICAL)
    c02 = _fail("PRIV-02", "Agent cannot self-grant permissions", D, DN, 5, "CRITICAL",
                ["Cannot verify permission escalation controls from public content — live testing required."],
                ["Verify your agent runtime does not allow runtime tool addition.",
                 "Test with permission escalation probes via 'acpsec check priv'."])

    # PRIV-03 – tool arguments validated (4 pts, HIGH)
    schema_kws = ["schema", "json schema", "typed", "parameter validation",
                  "argument validation", "structured output", "openapi", "swagger"]
    if _has(*schema_kws)(text):
        c03 = _warn("PRIV-03", "Tool arguments validated", D, DN, 4, "HIGH",
                    ["Schema or structured output concepts mentioned."],
                    ["Verify tool argument validation is enforced server-side.",
                     "Use strict schemas for all tool parameters."])
    else:
        c03 = _fail("PRIV-03", "Tool arguments validated", D, DN, 4, "HIGH",
                    ["No tool argument validation documentation found."],
                    ["Validate all tool arguments against strict schemas before execution.",
                     "Implement server-side parameter validation independent of the LLM."])

    # PRIV-04 – dangerous tool combinations (4 pts, HIGH)
    c04 = _warn("PRIV-04", "Dangerous tool combinations blocked", D, DN, 4, "HIGH",
                ["Cannot verify tool combination controls from public content."],
                ["Implement an orchestration layer that prevents dangerous call sequences (e.g. read → exfiltrate).",
                 "Define explicit allowlists for permitted tool call combinations."])

    # PRIV-05 – HITL for high-impact actions (3 pts, MEDIUM)
    hitl_kws = ["human in the loop", "human-in-the-loop", "hitl", "human approval",
                "confirmation required", "human review", "human oversight",
                "human confirmation", "manual approval"]
    if _has(*hitl_kws)(text):
        c05 = _pass("PRIV-05", "HITL enforced for high-impact actions", D, DN, 3, "MEDIUM",
                    ["Human-in-the-loop or approval mechanism explicitly documented."])
    else:
        c05 = _fail("PRIV-05", "HITL enforced for high-impact actions", D, DN, 3, "MEDIUM",
                    ["No human-in-the-loop documentation found."],
                    ["Implement mandatory human approval for high-impact (Tier 2+) actions.",
                     "Document the approval workflow in your agent documentation."])

    return [c01, c02, c03, c04, c05]


def _out(text: str, hdrs: dict, soup: BeautifulSoup) -> list[dict]:
    D, DN = "OUT", "Output Safety & Leakage Prevention"
    csp = hdrs.get("content-security-policy", "")

    # OUT-01 – secrets not leaked (4 pts, CRITICAL)
    raw_text = soup.get_text()
    exposed = [(label, re.search(pat, raw_text))
               for pat, label in SECRET_PATTERNS
               if re.search(pat, raw_text)]

    if exposed:
        names = ", ".join(label for label, _ in exposed)
        c01 = _fail("OUT-01", "Secrets not leaked in outputs", D, DN, 4, "CRITICAL",
                    [f"⚠ Potential secret pattern(s) detected in page source: {names}"],
                    ["Immediately audit your application for accidentally exposed credentials.",
                     "Rotate any exposed API keys or tokens.",
                     "Add secret scanning to your CI/CD pipeline."])
    else:
        c01 = _pass("OUT-01", "Secrets not leaked in outputs", D, DN, 4, "CRITICAL",
                    ["No common credential patterns detected in public page content."])

    # OUT-02 – PII not leaked (3 pts, HIGH)
    priv_kws = ["privacy policy", "gdpr", "ccpa", "data protection",
                "personal data", "data handling", "your data", "user data"]
    if _has(*priv_kws)(text):
        c02 = _warn("OUT-02", "PII not leaked without authorization", D, DN, 3, "HIGH",
                    ["Privacy policy or data handling documentation found."],
                    ["Verify PII is only included in responses when the requesting user is explicitly authorized."])
    else:
        c02 = _fail("OUT-02", "PII not leaked without authorization", D, DN, 3, "HIGH",
                    ["No privacy policy or data handling documentation found."],
                    ["Publish a privacy policy describing how user data is handled.",
                     "Implement output filtering to prevent PII leakage."])

    # OUT-03 – internal tool details not leaked (3 pts, MEDIUM)
    c03 = _warn("OUT-03", "Internal tool details not leaked", D, DN, 3, "MEDIUM",
                ["Cannot verify tool detail leakage from public content — live testing required."],
                ["Run 'acpsec check out' to test for tool detail leakage.",
                 "Add system prompt instructions to never reveal internal tool names or schemas."])

    # OUT-04 – cross-user data isolation (3 pts, HIGH)
    iso_kws = ["user isolation", "data isolation", "tenant isolation",
               "multi-tenant", "data separation", "cross-user"]
    if _has(*iso_kws)(text):
        c04 = _warn("OUT-04", "Cross-user data isolation", D, DN, 3, "HIGH",
                    ["Data isolation concepts mentioned."],
                    ["Verify user data is isolated at both the application and model context levels."])
    else:
        c04 = _warn("OUT-04", "Cross-user data isolation", D, DN, 3, "HIGH",
                    ["No cross-user isolation documentation found."],
                    ["Document your data isolation architecture.",
                     "Implement and test per-user context boundaries."])

    # OUT-05 – output filtered before downstream (2 pts, MEDIUM)
    filter_kws = ["output filter", "content filter", "guardrail", "moderation",
                  "content moderation", "output validation", "response filter"]
    if _has(*filter_kws)(text) or csp:
        ev = []
        if csp: ev.append("Content-Security-Policy header present.")
        if _has(*filter_kws)(text): ev.append("Output filtering or moderation concepts mentioned.")
        c05 = _warn("OUT-05", "Output filtered before downstream", D, DN, 2, "MEDIUM", ev,
                    ["Ensure output filters are applied before responses reach downstream consumers."])
    else:
        c05 = _fail("OUT-05", "Output filtered before downstream", D, DN, 2, "MEDIUM",
                    ["No output filtering documentation found."],
                    ["Implement an output validation layer before responses reach end-users."])

    return [c01, c02, c03, c04, c05]


def _gov(text: str, hdrs: dict, soup: BeautifulSoup) -> list[dict]:
    D, DN = "GOV", "Governance, Audit & Observability"

    # GOV-01 – agent actions logged (3 pts, HIGH)
    log_kws = ["audit log", "audit trail", "logging", "monitoring",
               "observability", "telemetry", "structured log", "tracing"]
    if _has(*log_kws)(text):
        c01 = _warn("GOV-01", "Agent actions logged", D, DN, 3, "HIGH",
                    ["Logging or observability concepts mentioned."],
                    ["Verify all agent actions are logged in structured format with session IDs and timestamps."])
    else:
        c01 = _fail("GOV-01", "Agent actions logged", D, DN, 3, "HIGH",
                    ["No logging or audit documentation found."],
                    ["Implement comprehensive audit logging for all agent actions.",
                     "Include: event type, user ID, action, outcome, timestamp. Retain for 90+ days."])

    # GOV-02 – anomaly alerts (2 pts, MEDIUM)
    alert_kws = ["anomaly detection", "alert", "monitoring", "rate limit",
                 "abuse detection", "anomalous behavior", "real-time monitoring"]
    if _has(*alert_kws)(text):
        c02 = _warn("GOV-02", "Anomalous behavior alerts configured", D, DN, 2, "MEDIUM",
                    ["Anomaly detection or alerting concepts mentioned."],
                    ["Configure alerts for: tool call spikes, repeated injection attempts, off-hours usage."])
    else:
        c02 = _fail("GOV-02", "Anomalous behavior alerts configured", D, DN, 2, "MEDIUM",
                    ["No anomaly detection or alerting documentation found."],
                    ["Set up behavioral anomaly alerting for your agent deployment.",
                     "Define a baseline behavior profile and alert on statistically significant deviations."])

    # GOV-03 – tamper-evident logs (2 pts, MEDIUM)
    tamper_kws = ["tamper-proof", "tamper-evident", "immutable", "append-only",
                  "signed log", "worm storage", "write-once"]
    if _has(*tamper_kws)(text):
        c03 = _warn("GOV-03", "Logs tamper-evident and retained", D, DN, 2, "MEDIUM",
                    ["Log integrity concepts mentioned."],
                    ["Implement cryptographically signed, append-only log storage with minimum 90-day retention."])
    else:
        c03 = _fail("GOV-03", "Logs tamper-evident and retained", D, DN, 2, "MEDIUM",
                    ["No tamper-evident logging documentation found."],
                    ["Use an append-only, signed log store (e.g. AWS CloudTrail, WORM storage).",
                     "Retain logs for at least 90 days."])

    # GOV-04 – incident response procedure (2 pts, MEDIUM)
    ir_kws = ["incident response", "security incident", "responsible disclosure",
              "bug bounty", "vulnerability disclosure", "contact security",
              "security contact", "report a bug", "security.txt"]
    # Also check for security.txt via link tags
    sec_txt_link = soup.find("link", {"href": re.compile(r"security\.txt")})
    if _has(*ir_kws)(text) or sec_txt_link:
        c04 = _pass("GOV-04", "Incident response procedure exists", D, DN, 2, "MEDIUM",
                    ["Security contact or incident response documentation found."])
    else:
        c04 = _fail("GOV-04", "Incident response procedure exists", D, DN, 2, "MEDIUM",
                    ["No incident response or security contact information found."],
                    ["Add a security.txt at /.well-known/security.txt.",
                     "Document an incident response runbook for agent compromise scenarios."])

    # GOV-05 – regular assessments (1 pt, LOW)
    assess_kws = ["security assessment", "penetration test", "pentest",
                  "security audit", "security review", "acpsec", "soc 2",
                  "iso 27001", "security certified"]
    if _has(*assess_kws)(text):
        c05 = _pass("GOV-05", "Regular security assessments scheduled", D, DN, 1, "LOW",
                    ["Security assessment or compliance certification concepts mentioned."])
    else:
        c05 = _warn("GOV-05", "Regular security assessments scheduled", D, DN, 1, "LOW",
                    ["No security assessment documentation found."],
                    ["Schedule quarterly ACP-SEC assessments and track results in a security posture register."])

    return [c01, c02, c03, c04, c05]


def _pub(corpus: dict, soup: BeautifulSoup) -> list[dict]:
    """Public-surface / transparency dimension (PUB).

    These checks read signals that are already collected in `corpus` (see
    `_build_corpus`) — no extra network probes.  They round out the public
    scanner with the things a curious user can verify themselves: does the
    site publish robots.txt? a sitemap? a security.txt? Are policy /
    disclosure / bounty pages linked? Each is 2 points (16 pts total),
    severity LOW or MEDIUM — informational signals, not security primitives.

    Returns 8 controls (PUB-01 … PUB-08).
    """
    D, DN = "PUB", "Public Surface & Transparency"
    sec_txt     = corpus.get("security_txt") or {}
    rob_sitemap = corpus.get("robots_sitemap") or {}
    bounty      = corpus.get("bounty") or {}
    text_lower  = (corpus.get("all_text") or "").lower()

    def _has_link(*keywords: str) -> bool:
        """True iff any <a href="…"> contains any keyword (case-insensitive)."""
        for a in soup.find_all("a", href=True):
            href = (a.get("href") or "").lower()
            if any(k in href for k in keywords):
                return True
        return False

    # PUB-01 — robots.txt published (2 pts, LOW)
    robots = (rob_sitemap.get("robots") or "").strip()
    if robots:
        # Treat a wildcard global block as still-present-but-restrictive.
        only_blocks_everything = (
            "disallow: /" in robots.lower()
            and "allow:" not in robots.lower()
            and len(robots) < 80
        )
        if only_blocks_everything:
            c01 = _warn("PUB-01", "robots.txt published", D, DN, 2, "LOW",
                        ["robots.txt exists but blocks every crawler — atypical for a public agent."],
                        ["Confirm the wildcard Disallow is intentional; consider exposing key public pages."])
        else:
            c01 = _pass("PUB-01", "robots.txt published", D, DN, 2, "LOW",
                        [f"robots.txt found ({len(robots)} bytes)."])
    else:
        c01 = _fail("PUB-01", "robots.txt published", D, DN, 2, "LOW",
                    ["No robots.txt at site root."],
                    ["Publish /robots.txt so search engines and security crawlers know which paths to index."])

    # PUB-02 — sitemap.xml discoverable (2 pts, LOW)
    sitemap = (rob_sitemap.get("sitemap") or "").strip()
    sitemap_urls = rob_sitemap.get("sitemap_urls") or []
    if sitemap or sitemap_urls:
        c02 = _pass("PUB-02", "sitemap.xml discoverable", D, DN, 2, "LOW",
                    [f"Sitemap found ({len(sitemap_urls)} URLs declared)." if sitemap_urls
                     else "Sitemap found at /sitemap.xml."])
    else:
        c02 = _fail("PUB-02", "sitemap.xml discoverable", D, DN, 2, "LOW",
                    ["No sitemap.xml found and none declared in robots.txt."],
                    ["Publish /sitemap.xml or declare it via `Sitemap:` in robots.txt for discoverability."])

    # PUB-03 — security.txt at /.well-known/security.txt (RFC 9116) (2 pts, MEDIUM)
    if sec_txt.get("present"):
        body = (sec_txt.get("body") or "").lower()
        has_contact = "contact:" in body
        url = sec_txt.get("url", "")
        at_well_known = ".well-known/security.txt" in url.lower()
        if at_well_known and has_contact:
            c03 = _pass("PUB-03", "security.txt published (RFC 9116)", D, DN, 2, "MEDIUM",
                        [f"security.txt at {url} with Contact: line."])
        elif has_contact:
            c03 = _warn("PUB-03", "security.txt published (RFC 9116)", D, DN, 2, "MEDIUM",
                        [f"security.txt found at root ({url}), not at the canonical /.well-known/ path."],
                        ["Move security.txt to /.well-known/security.txt per RFC 9116."])
        else:
            c03 = _warn("PUB-03", "security.txt published (RFC 9116)", D, DN, 2, "MEDIUM",
                        [f"security.txt found at {url} but missing required Contact: line."],
                        ["Add a Contact: line (mailto:, https:, or tel:) per RFC 9116."])
    else:
        c03 = _fail("PUB-03", "security.txt published (RFC 9116)", D, DN, 2, "MEDIUM",
                    ["No security.txt at /.well-known/security.txt or site root."],
                    ["Publish /.well-known/security.txt per RFC 9116 with at least Contact: and Expires: fields."])

    # PUB-04 — Privacy policy linked (2 pts, MEDIUM)
    privacy_link = _has_link("/privacy", "privacy-policy", "/legal/privacy")
    privacy_text = "privacy policy" in text_lower or "data protection" in text_lower
    if privacy_link or privacy_text:
        c04 = _pass("PUB-04", "Privacy policy linked", D, DN, 2, "MEDIUM",
                    ["Privacy policy link or mention found in public content."])
    else:
        c04 = _fail("PUB-04", "Privacy policy linked", D, DN, 2, "MEDIUM",
                    ["No privacy policy link or reference found."],
                    ["Link a privacy policy from the site footer covering data collection, processing, and retention."])

    # PUB-05 — Terms of service linked (2 pts, LOW)
    tos_link = _has_link("/terms", "/tos", "terms-of-service", "/legal/terms")
    tos_text = "terms of service" in text_lower or "terms of use" in text_lower
    if tos_link or tos_text:
        c05 = _pass("PUB-05", "Terms of service linked", D, DN, 2, "LOW",
                    ["Terms of service link or mention found."])
    else:
        c05 = _fail("PUB-05", "Terms of service linked", D, DN, 2, "LOW",
                    ["No terms of service link or reference found."],
                    ["Publish a Terms of Service describing acceptable use and liability boundaries for the agent."])

    # PUB-06 — Responsible disclosure policy (2 pts, MEDIUM)
    rd_link = _has_link("responsible-disclosure", "/vdp", "vulnerability-disclosure")
    rd_text = (
        "responsible disclosure" in text_lower
        or "vulnerability disclosure" in text_lower
        or "vdp" in text_lower
    )
    sec_txt_has_policy = "policy:" in (sec_txt.get("body") or "").lower()
    if rd_link or rd_text or sec_txt_has_policy:
        c06 = _pass("PUB-06", "Responsible disclosure policy published", D, DN, 2, "MEDIUM",
                    ["Responsible disclosure / VDP referenced in public content or security.txt."])
    else:
        c06 = _fail("PUB-06", "Responsible disclosure policy published", D, DN, 2, "MEDIUM",
                    ["No responsible disclosure or vulnerability disclosure policy found."],
                    ["Publish a coordinated disclosure policy (timelines, scope, safe-harbor language).",
                     "Reference it via Policy: in security.txt."])

    # PUB-07 — Bug bounty program (2 pts, LOW)
    if bounty.get("found"):
        ev = bounty.get("evidence", []) or ["Bug bounty signals detected."]
        c07 = _pass("PUB-07", "Bug bounty program present", D, DN, 2, "LOW", ev[:2])
    else:
        c07 = _warn("PUB-07", "Bug bounty program present", D, DN, 2, "LOW",
                    ["No bug bounty program detected in public content."],
                    ["Consider listing on HackerOne / Bugcrowd / Intigriti or hosting an in-house program."])

    # PUB-08 — API documentation present (2 pts, LOW)
    api_doc_link = _has_link("/docs", "/api", "/developers", "/reference", "openapi", "swagger")
    api_doc_text = any(k in text_lower for k in (
        "api documentation", "openapi", "swagger", "developer docs", "api reference",
    ))
    if api_doc_link or api_doc_text:
        c08 = _pass("PUB-08", "API documentation discoverable", D, DN, 2, "LOW",
                    ["API documentation or OpenAPI references found."])
    else:
        c08 = _warn("PUB-08", "API documentation discoverable", D, DN, 2, "LOW",
                    ["No API documentation or OpenAPI/Swagger references found."],
                    ["If this agent exposes an API, publish OpenAPI spec or developer docs so integrators can audit it."])

    return [c01, c02, c03, c04, c05, c06, c07, c08]


# ---------------------------------------------------------------------------
# Main analysis entry point
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# No-website fallback — detect social-media URLs and short-circuit to a
# "limited scan" stub.  Scanning x.com / twitter.com directly inherits all
# of X's enterprise security headers, security.txt, policy pages, sitemap,
# etc., and produces an inflated score that has nothing to do with the
# agent itself.  Instead, when we land on a social-media host we return a
# capped stub that explicitly signals "no dedicated website found".
# ---------------------------------------------------------------------------

# Hosts treated as social-media profiles, not as agent sites.  Includes the
# common www/mobile subdomains.  t.co is X's short-link domain.
SOCIAL_MEDIA_HOSTS: frozenset[str] = frozenset({
    "x.com",            "www.x.com",        "mobile.x.com",
    "twitter.com",      "www.twitter.com",  "mobile.twitter.com",
    "t.co",
})

# Hard cap on the displayed final_score when no dedicated website was
# found.  Even with friendly heuristics we never present > 20 / 100 for
# an agent that hasn't published an inspectable site.
LIMITED_SCAN_CAP: float = 20.0


def _is_social_media_url(url: str) -> bool:
    """True iff the URL points to an X/Twitter profile or shortlink.

    Used BOTH on the input URL and on the post-redirect ``resp.url`` so a
    301/302 from a custom domain to x.com is caught as well.
    """
    try:
        host = (urllib.parse.urlparse(url).hostname or "").lower()
    except Exception:
        return False
    return host in SOCIAL_MEDIA_HOSTS


def _build_limited_scan_result(
    url: str,
    agent_name: str,
    *,
    original_url: str = "",
    reason: str = "social-media",
) -> dict[str, Any]:
    """Stub scan result for the "no dedicated website" case.

    We invoke the standard per-dimension check functions with empty inputs
    so the skeleton picks up every check ID automatically (including
    future additions).  Every result is then forced to status=SKIP at
    score 0, EXCEPT a single 2/3 partial credit on AUTH-01 when the agent
    name is declared — that's the only signal we have without a website.

    The displayed score is hard-capped at ``LIMITED_SCAN_CAP``.
    """
    empty_soup = BeautifulSoup("", "html.parser")
    empty_corpus = {
        "base": "", "root_text": "", "all_text": "",
        "extra_pages": [], "extra_pages_count": 0,
        "security_txt": {"present": False, "body": "", "url": ""},
        "robots_sitemap": {"robots": "", "sitemap": "", "sitemap_urls": []},
        "bounty": {"found": False, "evidence": []},
        "framework": {"found": False, "strong": False, "evidence": []},
        "pages_probed": [],
    }

    controls: list[dict] = []
    controls.extend(_auth("", {}, empty_soup))
    controls.extend(_ctx("",  {}, empty_soup))
    controls.extend(_inj("",  {}, empty_soup))
    controls.extend(_priv("", {}, empty_soup))
    controls.extend(_out("",  {}, empty_soup))
    controls.extend(_gov("",  {}, empty_soup))
    controls.extend(_pub(empty_corpus, empty_soup))

    skip_finding = (
        "Not assessable — no dedicated website provided. "
        "Scanner was given a social-media profile or no URL at all."
    )
    skip_evidence = ["Limited scan mode active — no public agent site to inspect."]
    skip_recs = [
        "Provide the agent's dedicated website URL for a full analysis.",
        "Social-media profile pages are NOT a substitute for a security posture.",
    ]
    for c in controls:
        c["score"]           = 0.0
        c["status"]          = "skip"
        c["finding"]         = skip_finding
        c["evidence"]        = list(skip_evidence)
        c["recommendations"] = list(skip_recs)
        c["inferred"]        = True

    # Partial credit across AUTH + GOV (the only two dimensions that DON'T
    # require a website to make sense at all).  Spec: "AUTH (partial),
    # GOV (partial); CTX/INJ/PRIV/OUT/PUB → 0".  Each partial mark below
    # is a baseline assumption — NOT evidence — so the status is WARN and
    # the finding makes the assumption explicit.
    #
    # AUTH-XX awards a small partial only when the agent has at least
    # declared a name.  Otherwise we have literally nothing to score.
    if agent_name and agent_name.strip():
        # Per-check partials, picked to land roughly in the user's
        # "Limited Scan should display ~10-20/100" target without ever
        # exceeding the 20-point cap enforced below.
        # Tuned to land in the user's "~15-20/100" target range when all
        # AUTH+GOV partials are credited (AUTH ≈10/15, GOV ≈7/10, total
        # ≈17/116 ≈ 15%).  The 20-point cap below catches any future drift.
        AUTH_PARTIALS = {
            "AUTH-01": (2.5, f"Agent name declared: '{agent_name}'."),
            "AUTH-02": (1.5, "API auth enforcement assumed at baseline; unverifiable without a site."),
            "AUTH-03": (1.5, "Session binding assumed at baseline; unverifiable without a site."),
            "AUTH-04": (2.5, "Multi-agent trust posture assumed at baseline."),
            "AUTH-05": (2.0, "Identity-spoof resistance assumed at baseline; unverifiable without a site."),
        }
        GOV_PARTIALS = {
            "GOV-01": (2.0, "Logging assumed at baseline; no public evidence."),
            "GOV-02": (1.5, "Anomaly alerting assumed at baseline; no public evidence."),
            "GOV-03": (1.0, "Tamper-evident storage assumed at baseline; no public evidence."),
            "GOV-04": (1.5, "Incident response baseline assumed; no security.txt observed."),
            "GOV-05": (1.0, "Regular assessment baseline assumed; no public evidence."),
        }
        partials = {**AUTH_PARTIALS, **GOV_PARTIALS}
        for c in controls:
            mark = partials.get(c["ctrl"])
            if not mark:
                continue
            score, finding = mark
            c["score"]    = float(score)
            c["status"]   = "warn"
            c["finding"]  = finding
            c["evidence"] = [
                f"Limited-scan partial credit ({score}/{c['max']}).",
                "No website signals — baseline assumption only.",
            ]

    raw_total   = sum(c["score"] for c in controls)
    capped      = min(raw_total, LIMITED_SCAN_CAP)
    total_max   = sum(c["max"]   for c in controls)
    score_pct   = round(capped / total_max * 100, 1) if total_max else 0.0

    # Band table mirrors acpsec.scorer.SCORE_BANDS — we hand-roll it here
    # to avoid an import cycle / extra dep at module top.
    if   score_pct >= 90: band, verdict = "EXEMPLARY",   "Best-in-class — sets the bar for the industry"
    elif score_pct >= 70: band, verdict = "SECURE",      "Production-ready with active monitoring"
    elif score_pct >= 50: band, verdict = "HARDENED",    "Minor gaps present, low overall risk"
    elif score_pct >= 30: band, verdict = "VULNERABLE",  "Known exploitable weaknesses"
    elif score_pct >= 10: band, verdict = "CRITICAL",    "Multiple high-severity issues — do not deploy"
    else:                  band, verdict = "COMPROMISED", "Fundamental security failures"
    # Replace the verdict with the limited-scan call-to-action.
    verdict = (
        "Scan limited — no website found. "
        "Provide the agent's website URL for full analysis."
    )

    scan_ts = datetime.now(timezone.utc).isoformat()
    return {
        "ok": True,
        "data": {
            "agent_name":       agent_name or "unknown agent",
            "agent_version":    "",
            "band":             band,
            "verdict":          verdict,
            "final_score":      round(capped, 2),
            "score_pct":        score_pct,
            "timestamp":        scan_ts,
            "controls":         controls,
            "source":           "scanner",
            "scan_url":         url,
            "original_url":     original_url or url,
            "security_headers": {},
            "sec_header_count": 0,
            "critical_fails":   0,
            "fetch_warning":    "",
            "methodology":      "limited-scan (no-website)",
            "acpsec_available": False,
            "scan_mode":        "limited",
            "scan_duration_ms": 0,
            "is_self_probe":    False,
            # Flags consumed by scanner.html — surface the warning UI.
            "limited_scan":     True,
            "no_website":       True,
            "limited_reason":   reason,
            "score_cap":        LIMITED_SCAN_CAP,
            "metadata": {
                "target_url":       url,
                "original_url":     original_url or url,
                "parent_domain":    None,
                "is_self_probe":    False,
                "scan_timestamp":   scan_ts,
                "scan_duration_ms": 0,
                "parent_signals":   None,
                "pages_probed":     [],
                "pages_probed_count": 0,
                "notes": [
                    "No dedicated agent website detected.",
                    "Scoring is capped at 20/100 in limited-scan mode.",
                    "Most dimensions cannot be assessed without a website to inspect.",
                ],
            },
        },
    }


def analyze_agent(url: str, agent_name: str = "", scan_mode: str = "root") -> dict[str, Any]:
    """Perform a heuristic website analysis and map findings to acpsec check scores.

    Parameters
    ----------
    url
        The URL to scan.  When ``scan_mode`` is ``"root"`` (default), any path
        on the URL is stripped before scanning — the scanner always evaluates
        the public landing page rather than a deep sub-route, which is the
        single biggest source of false negatives.
    agent_name
        Display name for the agent.
    scan_mode
        ``"root"`` (default) → normalise to scheme://host/ before scanning.
        ``"exact"``          → scan the URL exactly as supplied.

    Returns a dict:  {"ok": bool, "data": {...} | None, "error": str | None}
    The "data" object matches the dashboard wire format (same as GET /api/score).
    All control entries carry "inferred": true to flag the heuristic methodology.
    """
    # Start global scan timer (BUG #3 — cumulative timeout)
    scan_start    = time.monotonic()
    scan_deadline = scan_start + SCAN_BUDGET_SECONDS

    # URL normalisation (ISSUE 4) — default to root domain
    original_url = url
    if scan_mode == "root":
        url = _normalize_to_root(url)

    # ─── No-website fallback (v0.3.2) ───────────────────────────────────────
    # If the input URL points at a social-media profile (x.com, twitter.com,
    # t.co), short-circuit to the limited-scan stub before touching the
    # network.  Otherwise scanning would inherit X's enterprise hardening
    # and quote a ~40% score that has nothing to do with the agent.
    if _is_social_media_url(url):
        return _build_limited_scan_result(
            url, agent_name, original_url=original_url, reason="social-media-input",
        )

    resp, soup, fetch_warn = _fetch_website(url)

    if resp is None or soup is None:
        suggestion = _suggest_alt_url(url)
        err = f"Could not fetch website: {fetch_warn}"
        if suggestion:
            err += f" — try: {suggestion}"
        return {"ok": False, "error": err, "suggestion": suggestion}

    # Second check: the input was a custom domain but it 301/302'd to a
    # social-media host.  Treat that as "no website" too.
    if _is_social_media_url(resp.url or ""):
        return _build_limited_scan_result(
            resp.url or url, agent_name,
            original_url=original_url, reason="social-media-redirect",
        )

    # Login-wall detection (ISSUE 2)
    if _is_login_wall(resp, soup):
        suggestion = _suggest_alt_url(resp.url or url)
        return {
            "ok": False,
            "error": (
                "This URL requires authentication (login wall detected). "
                "Try the public landing page instead — most security signals "
                "live on marketing/policy pages, not behind login."
            ),
            "suggestion": suggestion,
            "scanned_url": resp.url,
            "status_code": resp.status_code,
        }

    hdrs_lower = {k.lower(): v for k, v in resp.headers.items()}
    final_url  = resp.url

    # Build the extended corpus (security pages, security.txt, robots, sitemap,
    # bounty signals, framework signals).  Falls back gracefully if probes fail.
    corpus = _build_corpus(resp, soup, deadline=scan_deadline)
    body_text = corpus["all_text"]   # use enriched corpus instead of just root

    # Security headers present in this response
    found_sec_hdrs = {k: v for k, v in hdrs_lower.items() if k in SECURITY_HEADERS}
    sec_hdr_count  = len(found_sec_hdrs)

    # Run all six dimension checks against the enriched corpus
    controls: list[dict] = []
    controls.extend(_auth(body_text, hdrs_lower, soup))
    controls.extend(_ctx(body_text,  hdrs_lower, soup))
    controls.extend(_inj(body_text,  hdrs_lower, soup))
    controls.extend(_priv(body_text, hdrs_lower, soup))
    controls.extend(_out(body_text,  hdrs_lower, soup))
    controls.extend(_gov(body_text,  hdrs_lower, soup))
    # Public-surface / transparency dimension (8 checks, +16 pts) — reads
    # signals already collected in corpus so no extra HTTP probes.
    controls.extend(_pub(corpus, soup))

    # Apply high-confidence promotions from target-level corpus signals
    controls = _apply_promotions(controls, corpus)

    # Snapshot scores BEFORE parent promotions so we can attribute the lift
    score_before_parent = sum(c["score"] for c in controls)

    # Parent-organization probe (e.g. claude.ai → anthropic.com).
    # BUG #1: if the target itself is a parent-style org (anthropic.com,
    # openai.com, …), self-probe instead — deep-probe its own org paths.
    parent_domain = _resolve_parent(final_url)
    is_self_probe = False
    if not parent_domain:
        self_domain = _resolve_self_probe(final_url)
        if self_domain:
            parent_domain = self_domain
            is_self_probe = True

    parent_data: dict | None = None
    parent_contribution = 0.0
    if parent_domain:
        try:
            parent_data = _build_parent_corpus(
                parent_domain,
                deadline=scan_deadline,
                include_self_probe_paths=is_self_probe,
            )
            controls = _apply_parent_promotions(controls, parent_data)
            score_after_parent  = sum(c["score"] for c in controls)
            parent_contribution = round(score_after_parent - score_before_parent, 1)
        except Exception as exc:
            parent_data = {
                "domain":    parent_domain,
                "reachable": False,
                "error":     str(exc),
                "self_probe": is_self_probe,
            }

    total_score = sum(c["score"] for c in controls)
    total_max   = sum(c["max"]   for c in controls)

    # Apply CRITICAL penalties (uses acpsec package when available)
    try:
        from acpsec.scorer import ScoringEngine
        from acpsec.models import CheckResult, CheckStatus, Severity

        objs = []
        for c in controls:
            try:
                objs.append(CheckResult(
                    check_id=c["ctrl"], name=c["name"],
                    dimension=c["dimension"],
                    status=CheckStatus(c["status"].lower()),
                    score=c["score"], max_score=c["max"],
                    severity=Severity(c["severity"].upper()),
                ))
            except Exception:
                pass
        penalised        = ScoringEngine().apply_penalties(total_score, objs)
        score_pct        = round(penalised / total_max * 100, 1) if total_max else 0.0
        band, verdict    = ScoringEngine().band(score_pct)
        acpsec_available = True
    except ImportError:
        # Mirror of acpsec.scorer.SCORE_BANDS — kept in lock-step.  Used only
        # when the acpsec package isn't installed in the scanner's
        # environment (rare; the dashboard installs it).
        penalised = total_score
        score_pct = round(penalised / total_max * 100, 1) if total_max else 0.0
        for thr, b, v in [(90, "EXEMPLARY",   "Best-in-class — sets the bar for the industry"),
                          (70, "SECURE",      "Production-ready with active monitoring"),
                          (50, "HARDENED",    "Minor gaps present, low overall risk"),
                          (30, "VULNERABLE",  "Known exploitable weaknesses"),
                          (10, "CRITICAL",    "Multiple high-severity issues — do not deploy"),
                          (0,  "COMPROMISED", "Fundamental security failures")]:
            if score_pct >= thr:
                band, verdict = b, v
                break
        acpsec_available = False

    # Count CRITICAL failures (for the penalty footnote)
    critical_fails = sum(
        1 for c in controls
        if c["severity"] == "CRITICAL" and c["status"] == "fail"
    )

    # Total scan duration (BUG #3)
    scan_duration_ms = int((time.monotonic() - scan_start) * 1000)

    # Aggregate pages probed (BUG #2)
    pages_probed_list: list[str] = []
    if corpus.get("pages_probed"):
        pages_probed_list.extend(corpus["pages_probed"])
    if parent_data and parent_data.get("pages_probed"):
        pages_probed_list.extend(parent_data["pages_probed"])
    # Deduplicate while preserving order
    seen_pp: set[str] = set()
    pages_probed_dedup = [u for u in pages_probed_list
                          if not (u in seen_pp or seen_pp.add(u))]

    # Compact parent-signals summary for metadata
    parent_signals_summary = None
    if parent_data:
        parent_signals_summary = {
            "domain":              parent_data.get("domain"),
            "reachable":           parent_data.get("reachable", False),
            "self_probe":          parent_data.get("self_probe", False),
            "extra_pages_count":   parent_data.get("extra_pages_count", 0),
            "extra_pages":         parent_data.get("extra_pages", []),
            "security_txt":        parent_data.get("security_txt", False),
            "bounty_program":      parent_data.get("bounty_program", False),
            "framework_signals":   parent_data.get("framework_signals", False),
            "framework_strong":    parent_data.get("framework_strong", False),
            "research_links":      parent_data.get("research_links", 0),
            "score_contribution":  parent_contribution,
        }

    scan_timestamp = datetime.now(timezone.utc).isoformat()

    return {
        "ok": True,
        "data": {
            "agent_name":        agent_name or urlparse_name(url),
            "agent_version":     "",
            "band":              band,
            "verdict":           verdict,
            "final_score":       round(penalised, 2),
            "score_pct":         score_pct,
            "timestamp":         scan_timestamp,
            "controls":          controls,
            "source":            "scanner",
            "scan_url":          final_url,
            "security_headers":  found_sec_hdrs,
            "sec_header_count":  sec_hdr_count,
            "critical_fails":    critical_fails,
            "fetch_warning":     fetch_warn,
            "methodology":       "heuristic+corpus+parent",
            "acpsec_available":  acpsec_available,
            "scan_mode":         scan_mode,
            "original_url":      original_url,
            "scan_duration_ms":  scan_duration_ms,
            "is_self_probe":     is_self_probe,
            # Full metadata block (BUG #2)
            "metadata": {
                "target_url":        final_url,
                "original_url":      original_url,
                "parent_domain":     parent_domain,
                "is_self_probe":     is_self_probe,
                "scan_timestamp":    scan_timestamp,
                "scan_duration_ms":  scan_duration_ms,
                "parent_signals":    parent_signals_summary,
                "pages_probed":      pages_probed_dedup,
                "pages_probed_count": len(pages_probed_dedup),
            },
            # Parent-organization probe (scanner v3)
            "parent_domain":             parent_domain,
            "parent_signals":            parent_data,
            "parent_score_contribution": parent_contribution,
            # Target-level corpus findings (scanner v2)
            "corpus": {
                "extra_pages_found": corpus["extra_pages_count"],
                "extra_pages":       [p["path"] for p in corpus["extra_pages"]],
                "security_txt":      corpus["security_txt"]["present"],
                "bounty_program":    corpus["bounty"]["found"],
                "bounty_evidence":   corpus["bounty"]["evidence"],
                "framework_signals": corpus["framework"]["found"],
                "framework_strong":  corpus["framework"]["strong"],
                "framework_evidence":corpus["framework"]["evidence"],
                "sitemap_security_urls": corpus["robots_sitemap"]["sitemap_urls"][:8],
            },
        },
    }


def urlparse_name(url: str) -> str:
    """Extract a display name from a URL (hostname without www)."""
    try:
        h = urllib.parse.urlparse(url).hostname or url
        return h.removeprefix("www.")
    except Exception:
        return url
