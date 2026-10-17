#!/usr/bin/env python3
"""Find websites that imitate this project's name or its GitHub Pages site,
and open a tracking issue in this repository for each one."""

import concurrent.futures as cf
import json
import os
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from typosquat_watch import get, paginate, post, summary, variants  # noqa: E402

ORIGINAL = os.environ["ORIGINAL_REPO"]
DRY_RUN = os.environ.get("DRY_RUN", "true").lower() == "true"
SITE_URL = os.environ.get("SITE_URL", "").strip()
KEYWORDS = os.environ.get("KEYWORDS", "").split()
CT_KEYWORDS = os.environ.get("CT_KEYWORDS", "").split()
TLDS = os.environ.get("TLDS", "com net org io app dev").split()
MARKERS = [m.strip().lower() for m in os.environ.get("CONTENT_MARKERS", "").split("|") if m.strip()]
ALLOWLIST = {h.lower() for h in os.environ.get("ALLOWLIST", "").split()}
LABEL = "typosquat-site"
MARKER = "<!-- typosquat-site:{} -->"
UA = f"Mozilla/5.0 (compatible; typosquat-site-watch; +https://github.com/{ORIGINAL})"
HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$")
DOWNLOAD_EXT = re.compile(r"\.(dmg|pkg|zip|app|exe|iso)(\?|#|$)", re.I)

socket.setdefaulttimeout(10)


# --------------------------------------------------------------- network --

def resolve(host):
    try:
        return sorted({ai[4][0] for ai in socket.getaddrinfo(host, 443)})
    except (OSError, UnicodeError):
        return []


def fetch(url, limit=2_000_000):
    """GET a page without running anything. Returns (status, final_url, html)."""
    for ctx in (ssl.create_default_context(), ssl._create_unverified_context()):
        req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "text/html"})
        try:
            with urllib.request.urlopen(req, timeout=15, context=ctx) as r:
                ctype = r.headers.get("Content-Type", "")
                body = r.read(limit) if ("html" in ctype or "text" in ctype) else b""
                return r.status, r.geturl(), body.decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, url, ""
        except urllib.error.URLError as e:
            if isinstance(e.reason, ssl.SSLError):
                continue  # retry once without certificate verification
            break
        except Exception:
            break
    return None, url, ""


def fetch_json(url, timeout=30):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


# ------------------------------------------------------------- discovery --

def site_info(owner, name):
    pages = get(f"/repos/{ORIGINAL}/pages") or {}
    url = SITE_URL or pages.get("html_url") or f"https://{owner}.github.io/{name}/"
    parts = urllib.parse.urlsplit(url)
    return url, parts.hostname.lower(), parts.path or "/"


def domain_candidates(keywords):
    hosts = set()
    for kw in keywords:
        for v in variants(kw):
            if HOST_LABEL.match(v):
                hosts.update(f"{v}.{tld}" for tld in TLDS)
    return hosts


def ct_hosts(keyword):
    """Hostnames from certificate-transparency logs that contain the keyword."""
    q = urllib.parse.quote(f"%{keyword}%")
    url = f"https://crt.sh/?q={q}&output=json&exclude=expired&deduplicate=Y"
    for attempt in range(3):
        try:
            rows = fetch_json(url, timeout=90)
            names = set()
            for row in rows:
                for n in (row.get("name_value") or "").split("\n"):
                    n = n.strip().lower().lstrip("*.")
                    if n and "@" not in n:
                        names.add(n)
            return names
        except Exception as e:
            print(f"  crt.sh attempt {attempt + 1} for '{keyword}' failed: {e}")
            time.sleep(15)
    print(f"::warning::Certificate-transparency lookup for '{keyword}' failed; skipped this run.")
    return set()


def github_pages_candidates(site_host, site_path):
    """Lookalike <user>.github.io accounts that actually exist."""
    if not site_host.endswith(".github.io"):
        return {}
    user = site_host.split(".")[0]
    found = {}
    for v in variants(user):
        if v != user and HOST_LABEL.match(v) and get(f"/users/{v}"):
            found[f"{v}.github.io"] = site_path
    return found


# ------------------------------------------------------------ inspection --

def allowed(host, site_host):
    return host == site_host or any(host == a or host.endswith("." + a) for a in ALLOWLIST)


def inspect(host, path):
    ips = resolve(host)
    if not ips:
        return None
    status, final, html = fetch(f"https://{host}{path}")
    if not html:
        status, final, html = fetch(f"http://{host}{path}")
    if not html:
        return None
    low = html.lower()
    hits = [m for m in MARKERS if m in low]
    if not hits:
        return None  # resolves, but doesn't present itself as this project
    title = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    links = re.findall(r"""href\s*=\s*["']([^"']+)""", html, re.I)
    dl_hosts = sorted({urllib.parse.urlsplit(urllib.parse.urljoin(final, link)).hostname or "?"
                       for link in links if DOWNLOAD_EXT.search(link)})
    return {
        "host": host, "url": final, "status": status, "ips": ips,
        "title": re.sub(r"\s+", " ", title.group(1)).strip()[:150] if title else "",
        "markers": hits, "download_hosts": dl_hosts,
        "links_official": f"github.com/{ORIGINAL}".lower() in low,
    }


def rdap(host):
    """Registrar, abuse contact and registration date (best effort)."""
    domain = ".".join(host.split(".")[-2:])
    try:
        data = fetch_json(f"https://rdap.org/domain/{domain}")
    except Exception:
        return {}

    def vcard(entity, key):
        for item in (entity.get("vcardArray") or [None, []])[1]:
            if item and item[0] == key:
                return item[3]
        return None

    info = {}
    for ent in data.get("entities", []):
        if "registrar" in ent.get("roles", []):
            info["registrar"] = vcard(ent, "fn")
            for sub in ent.get("entities", []):
                if "abuse" in sub.get("roles", []):
                    info["abuse"] = vcard(sub, "email")
    for ev in data.get("events", []):
        if ev.get("eventAction") == "registration":
            info["registered"] = ev.get("eventDate", "")[:10]
    return info


# ----------------------------------------------------------------- texts --

def issue_body(r, reg):
    if r["host"].endswith(".github.io"):
        account = r["host"].split(".")[0]
        where = f"GitHub Pages site of the account [`{account}`](https://github.com/{account})"
        action = ("Report the account or its Pages repository to GitHub "
                  "(**Report repository** / **Block or report** on their profile).")
    else:
        where = "independent domain"
        contact = f" ({reg['abuse']})" if reg.get("abuse") else ""
        action = ("If it impersonates the project, report it to the registrar's abuse contact"
                  f"{contact} and the hosting provider, and submit it to "
                  "[Google Safe Browsing](https://safebrowsing.google.com/safebrowsing/report_phish/).")
    lines = [
        f"Found a website with a lookalike name that presents itself as this project: **{r['host']}**",
        "",
        f"- **URL:** {r['url']} (HTTP {r['status']})",
        f"- **Type:** {where}",
        f"- **Page title:** {r['title'] or '—'}",
        f"- **Matched text:** {', '.join(f'`{m}`' for m in r['markers'])}",
        f"- **Links to the official repo:** {'yes' if r['links_official'] else 'no'}",
        f"- **Download links point to:** {', '.join(r['download_hosts']) or 'no download links'}",
        f"- **IP addresses:** {', '.join(r['ips'])}",
    ]
    if reg:
        lines += [
            f"- **Registrar:** {reg.get('registrar') or '—'}",
            f"- **Registrar abuse contact:** {reg.get('abuse') or '—'}",
            f"- **Registered:** {reg.get('registered') or '—'}",
        ]
    lines += [
        "",
        "A matching name and project text don't prove bad intent; it may be a fan page or a mirror. "
        "Please check the site before acting.",
        "",
        f"**If it's an impersonation:** {action}",
        "",
        "Closing this issue marks the site as handled, and the workflow won't file it again.",
        "",
        MARKER.format(r["host"]),
    ]
    return "\n".join(lines)


# ------------------------------------------------------------------ main --

def main():
    repo = get(f"/repos/{ORIGINAL}")
    owner, name = repo["owner"]["login"], repo["name"]
    site_url, site_host, site_path = site_info(owner, name)
    keywords = KEYWORDS or [name.lower(), name.lower().replace("-", "")]

    summary(f"## Lookalike site scan for `{site_url}`" + (" (dry run)" if DRY_RUN else ""))

    targets = {h: "/" for h in domain_candidates(keywords)}
    for kw in CT_KEYWORDS:
        for h in ct_hosts(kw):
            targets.setdefault(h, "/")
    targets.update(github_pages_candidates(site_host, site_path))
    targets = {h: p for h, p in targets.items() if not allowed(h, site_host)}
    print(f"{len(targets)} hostnames to check")

    with cf.ThreadPoolExecutor(max_workers=48) as ex:
        results = [r for r in ex.map(lambda hp: inspect(*hp), targets.items()) if r]

    tracked = set()
    for issue in paginate(f"/repos/{ORIGINAL}/issues?labels={LABEL}&state=all&per_page=100"):
        m = re.search(r"<!-- typosquat-site:(\S+) -->", issue.get("body") or "")
        if m:
            tracked.add(m.group(1).lower())

    new = [r for r in sorted(results, key=lambda r: r["host"]) if r["host"] not in tracked]
    if new and not DRY_RUN:
        post(f"/repos/{ORIGINAL}/labels",
             {"name": LABEL, "color": "b60205", "description": "Website imitating this project"})

    for r in new:
        summary(f"- **{r['host']}** — {r['title'] or 'no title'}; matched "
                + ", ".join(f"`{m}`" for m in r["markers"]))
        if DRY_RUN:
            continue
        reg = {} if r["host"].endswith(".github.io") else rdap(r["host"])
        status, _ = post(f"/repos/{ORIGINAL}/issues", {
            "title": f"Lookalike site: {r['host']}",
            "body": issue_body(r, reg),
            "labels": [LABEL],
        })
        if status >= 300:
            print(f"::error::Could not open an issue for {r['host']} (HTTP {status})")
        time.sleep(3)

    summary(f"\n{len(new)} new lookalike sites found ({len(results)} matching in total).")


if __name__ == "__main__":
    main()
