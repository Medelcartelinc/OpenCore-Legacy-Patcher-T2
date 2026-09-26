#!/usr/bin/env python3
"""Checks new/edited issues for hate speech. If flagged: deletes the issue,
blocks the author and records it in moderation/flagged-issues.md.
Standard library only."""
import json
import os
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORDLIST = ROOT / ".github" / "moderation" / "blocked_terms.txt"
LOG = ROOT / "moderation" / "flagged-issues.md"
API = "https://api.github.com"
TOKEN = os.environ.get("GH_TOKEN", "")
REPO = os.environ["REPO"]
HEADER = (
    "# Flagged issues\n\n"
    "Issues automatically removed for hate speech. The issue text is not stored here. "
    "Set *Reported* to ✅ after reporting the user to GitHub.\n\n"
    "| Date (UTC) | Issue | User | Detection | Reason | Issue removed | User blocked | Report link | Reported |\n"
    "|---|---|---|---|---|---|---|---|---|\n"
)


def gh(method, path, body=None):
    req = urllib.request.Request(
        API + path,
        method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={
            "Authorization": f"Bearer {TOKEN}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.urlopen(req) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")


def wordlist_hits(text):
    if not WORDLIST.exists():
        return []
    terms = [
        t.strip().lower()
        for t in WORDLIST.read_text(encoding="utf-8").splitlines()
        if t.strip() and not t.strip().startswith("#")
    ]
    low = text.lower()
    return [t for t in terms if re.search(rf"(?<!\w){re.escape(t)}(?!\w)", low)]


def claude_verdict(text):
    """Returns {"hate_speech": bool, "reason": str} or None if unavailable."""
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        return None
    prompt = (
        "You are a content moderator for an open-source GitHub repository. "
        "Decide whether the issue text below contains hate speech: attacks, slurs "
        "or dehumanising language targeting people for race, ethnicity, nationality, "
        "religion, sex, gender identity, sexual orientation, disability or similar. "
        "Rudeness, swearing or frustration about software is NOT hate speech. "
        "Do not quote the offending text in your reason. "
        'Reply with JSON only: {"hate_speech": true|false, "reason": "<short>"}\n\n'
        "<issue>\n" + text[:8000] + "\n</issue>"
    )
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        method="POST",
        data=json.dumps({
            "model": "claude-haiku-4-5",
            "max_tokens": 200,
            "messages": [{"role": "user", "content": prompt}],
        }).encode(),
        headers={
            "x-api-key": key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            out = json.loads(r.read())["content"][0]["text"]
        return json.loads(re.search(r"\{.*\}", out, re.S).group(0))
    except Exception as e:  # fall back to the word list
        print(f"Claude check failed: {e}")
        return None


def remove_issue(issue):
    """Deletes the issue (needs admin token); falls back to wipe + close + lock."""
    status, resp = gh("POST", "/graphql", {
        "query": "mutation($id:ID!){deleteIssue(input:{issueId:$id}){clientMutationId}}",
        "variables": {"id": issue["node_id"]},
    })
    if status == 200 and isinstance(resp, dict) and not resp.get("errors"):
        return "✅ deleted"
    print(f"Delete failed ({status}): {resp} - falling back to wipe/close/lock")
    n = issue["number"]
    gh("PATCH", f"/repos/{REPO}/issues/{n}", {
        "title": "[removed by moderation]",
        "body": "_This issue was removed for violating the code of conduct._",
        "state": "closed",
        "state_reason": "not_planned",
    })
    gh("PUT", f"/repos/{REPO}/issues/{n}/lock", {"lock_reason": "too heated"})
    return "⚠️ wiped + locked"


def cell(s):
    return str(s).replace("|", "/").replace("\n", " ").strip()


def main():
    if not TOKEN:
        sys.exit("MODERATION_TOKEN secret is not set")

    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    issue, user = event["issue"], event["issue"]["user"]
    text = f"{issue.get('title', '')}\n\n{issue.get('body') or ''}"

    hits = wordlist_hits(text)
    verdict = claude_verdict(text)
    if verdict is not None:
        flagged, reason, method = bool(verdict.get("hate_speech")), verdict.get("reason", ""), "Claude"
    else:
        flagged, reason, method = bool(hits), f"{len(hits)} blocked term(s)", "word list"

    if not flagged:
        print("Issue is clean.")
        return

    action = remove_issue(issue)
    block_status, _ = gh("PUT", f"/user/blocks/{user['login']}")
    blocked = "✅" if block_status == 204 else f"❌ ({block_status})"

    row = "| " + " | ".join([
        datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M"),
        f"#{issue['number']}",
        f"[@{user['login']}]({user['html_url']}) (ID {user['id']})",
        method,
        cell(reason),
        action,
        blocked,
        f"[Report](https://github.com/contact/report-abuse?report={user['login']})",
        "❌",
    ]) + " |\n"

    existing = LOG.read_text(encoding="utf-8") if LOG.exists() else HEADER
    LOG.parent.mkdir(parents=True, exist_ok=True)
    LOG.write_text(existing + row, encoding="utf-8")
    print(f"::warning::Hate speech by @{user['login']} in #{issue['number']}: "
          f"issue {action}, blocked {blocked}. Report: "
          f"https://github.com/contact/report-abuse?report={user['login']}")


if __name__ == "__main__":
    main()
