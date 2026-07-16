#!/usr/bin/env python3
"""Create Jira stories in VULN for code scanning alerts merged to production.

Stdlib only — no pip installs, no supply-chain surface. Runs in GitHub Actions.

Modes
-----
DRY_RUN=true  (default): builds the exact POST /rest/api/3/issue payload,
              prints it, writes it to the job summary and jira-payloads/
              — no Jira credentials needed. Build & test everything now.
DRY_RUN=false: dedup-checks via JQL, creates the story, posts Slack alert.
              Works identically with a personal API token or the service
              account — swapping accounts is a secrets-only change.

Field facts verified against the live VULN project (2026-07-16):
  - team-managed project, id 17538
  - Story issue type id 17745
  - required create fields: project, issuetype, summary (reporter defaults)
  - NO Priority field on the create screen -> severity goes in labels + description
"""

import fnmatch
import json
import os
import sys
import urllib.error
import urllib.request
from base64 import b64encode
from datetime import datetime, timezone
from pathlib import Path

# --------------------------------------------------------------------------- config

DRY_RUN = os.environ.get("DRY_RUN", "true").strip().lower() != "false"
JIRA_BASE_URL = os.environ.get("JIRA_BASE_URL", "").rstrip("/")
JIRA_EMAIL = os.environ.get("JIRA_EMAIL", "")
JIRA_API_TOKEN = os.environ.get("JIRA_API_TOKEN", "")
PROJECT_KEY = os.environ.get("JIRA_PROJECT_KEY", "VULN")
ISSUE_TYPE_ID = os.environ.get("JIRA_ISSUE_TYPE_ID", "17745")  # Story in VULN
SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL", "")
PAYLOAD_DIR = Path("jira-payloads")

SEVERITY_ORDER = ["critical", "high", "medium", "low", "warning", "note", "error"]

# --------------------------------------------------------------------------- alerts


def load_alerts():
    """Yield (alert, repo_full_name) from the GitHub event or a fixture file."""
    fixture = os.environ.get("ALERT_FIXTURE", "")
    event_path = os.environ.get("GITHUB_EVENT_PATH", "")
    event_name = os.environ.get("GITHUB_EVENT_NAME", "")

    if event_name == "code_scanning_alert" and event_path:
        event = json.loads(Path(event_path).read_text())
        yield event["alert"], event["repository"]["full_name"]
        return

    if fixture and Path(fixture).exists():
        data = json.loads(Path(fixture).read_text())
        for item in data if isinstance(data, list) else [data]:
            yield item["alert"], item["repository"]["full_name"]
        return

    print("::error::No code_scanning_alert event and no fixture found. Nothing to do.")
    sys.exit(1)


def severity_of(alert):
    rule = alert.get("rule", {})
    sev = (rule.get("security_severity_level") or rule.get("severity") or "unknown").lower()
    return sev if sev in SEVERITY_ORDER else "unknown"


def location_of(alert):
    loc = alert.get("most_recent_instance", {}).get("location", {})
    return loc.get("path", "unknown"), loc.get("start_line", 0)


# ----------------------------------------------------------------------- CODEOWNERS


def suggest_owner(path):
    """Last-match-wins CODEOWNERS lookup (approximation of gitignore semantics).

    Swap in the audited matcher from org_audit.py when convenient — the
    interface (path in, owner string out) is identical.
    """
    for candidate in (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"):
        f = Path(candidate)
        if not f.exists():
            continue
        owner = None
        for line in f.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            pattern, owners = parts[0], parts[1:]
            pat = pattern.lstrip("/")
            if pat.endswith("/"):
                pat += "**"
            if fnmatch.fnmatch(path, pat) or fnmatch.fnmatch(path, pat + "/*") or fnmatch.fnmatch("/" + path, pattern):
                owner = " ".join(owners) if owners else None
        return owner or "NO MATCHING OWNER"
    return "NO CODEOWNERS FILE"


# -------------------------------------------------------------------------- payload


def dedup_label(repo, alert_number):
    # Jira labels cannot contain spaces; keep it deterministic & queryable.
    return f"gh-{repo.replace('/', '-')}-alert-{alert_number}".lower()


def adf_text(text, bold=False):
    node = {"type": "text", "text": text}
    if bold:
        node["marks"] = [{"type": "strong"}]
    return node


def build_payload(alert, repo):
    sev = severity_of(alert)
    path, line = location_of(alert)
    rule = alert.get("rule", {})
    number = alert.get("number", 0)
    url = alert.get("html_url", "")
    owner = suggest_owner(path)

    summary = f"[{sev.upper()}] {rule.get('id', 'unknown-rule')} in {repo} — {path}"[:255]

    facts = [
        ("Severity", sev.upper()),
        ("Repository", repo),
        ("Location", f"{path}:{line}"),
        ("Rule", f"{rule.get('id', '?')} — {rule.get('description', rule.get('name', ''))}"),
        ("Tool", alert.get("tool", {}).get("name", "CodeQL")),
        ("Suggested owner (CODEOWNERS)", owner),
        ("Alert", url or f"alert #{number}"),
    ]

    description = {
        "type": "doc",
        "version": 1,
        "content": [
            {
                "type": "paragraph",
                "content": [adf_text(
                    "Auto-created: a code scanning alert reached the default branch. "
                    "Clone this story to your team's home board to schedule the fix."
                )],
            },
            {
                "type": "bulletList",
                "content": [
                    {
                        "type": "listItem",
                        "content": [{
                            "type": "paragraph",
                            "content": [adf_text(f"{k}: ", bold=True), adf_text(str(v))],
                        }],
                    }
                    for k, v in facts
                ],
            },
        ],
    }

    return {
        "fields": {
            "project": {"key": PROJECT_KEY},
            "issuetype": {"id": ISSUE_TYPE_ID},
            "summary": summary,
            "description": description,
            # VULN has no Priority field on the create screen (team-managed
            # project) — severity is carried in labels + description instead.
            "labels": ["vuln-auto", f"severity-{sev}", dedup_label(repo, number)],
        }
    }


# ----------------------------------------------------------------------------- jira


def jira_request(method, api_path, body=None):
    auth = b64encode(f"{JIRA_EMAIL}:{JIRA_API_TOKEN}".encode()).decode()
    req = urllib.request.Request(
        f"{JIRA_BASE_URL}{api_path}",
        data=json.dumps(body).encode() if body is not None else None,
        method=method,
        headers={
            "Authorization": f"Basic {auth}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        print(f"::error::Jira {method} {api_path} -> {e.code}: {e.read().decode()[:500]}")
        raise


def find_existing(label):
    body = {
        "jql": f'project = {PROJECT_KEY} AND labels = "{label}"',
        "maxResults": 1,
        "fields": ["key"],
    }
    result = jira_request("POST", "/rest/api/3/search/jql", body)
    issues = result.get("issues", [])
    return issues[0]["key"] if issues else None


# ---------------------------------------------------------------------------- slack


def slack_notify(issue_key, alert, repo):
    if not SLACK_WEBHOOK_URL:
        print("SLACK_WEBHOOK_URL not set — skipping Slack notification.")
        return
    sev = severity_of(alert)
    path, _ = location_of(alert)
    owner = suggest_owner(path)
    issue_url = f"{JIRA_BASE_URL}/browse/{issue_key}" if issue_key else "(dry run)"
    message = {
        "text": (
            f":rotating_light: *New vulnerability story created:* "
            f"<{issue_url}|{issue_key or 'DRY-RUN'}>\n"
            f"*Severity:* {sev.upper()}  •  *Repo:* {repo}  •  *File:* {path}\n"
            f"*Suggested owner:* {owner}\n"
            f"_Owner: please clone this story to your home board._"
        )
    }
    if DRY_RUN:
        print(f"[dry-run] Slack message:\n{json.dumps(message, indent=2)}")
        return
    req = urllib.request.Request(
        SLACK_WEBHOOK_URL,
        data=json.dumps(message).encode(),
        headers={"Content-Type": "application/json"},
    )
    urllib.request.urlopen(req, timeout=15)
    print(f"Slack notification sent for {issue_key}.")


# -------------------------------------------------------------------------- summary


def write_summary(rows):
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    lines = [
        f"## Vuln → Jira Story {'(DRY RUN)' if DRY_RUN else ''}",
        "",
        "| Repo | Severity | Rule | Result |",
        "| --- | --- | --- | --- |",
        *rows,
        "",
        f"_Run at {datetime.now(timezone.utc).isoformat()}_",
    ]
    text = "\n".join(lines)
    if summary_path:
        with open(summary_path, "a") as f:
            f.write(text + "\n")
    print(text)


# ----------------------------------------------------------------------------- main


def main():
    if not DRY_RUN and not (JIRA_BASE_URL and JIRA_EMAIL and JIRA_API_TOKEN):
        print("::error::DRY_RUN=false but Jira credentials are missing.")
        sys.exit(1)

    PAYLOAD_DIR.mkdir(exist_ok=True)
    rows = []

    for alert, repo in load_alerts():
        payload = build_payload(alert, repo)
        sev = severity_of(alert)
        rule_id = alert.get("rule", {}).get("id", "?")
        label = dedup_label(repo, alert.get("number", 0))

        out = PAYLOAD_DIR / f"{label}.json"
        out.write_text(json.dumps(payload, indent=2))

        if DRY_RUN:
            print(f"[dry-run] would create issue:\n{json.dumps(payload, indent=2)}")
            rows.append(f"| {repo} | {sev} | {rule_id} | dry-run: payload saved to `{out}` |")
            slack_notify(None, alert, repo)
            continue

        existing = find_existing(label)
        if existing:
            print(f"Duplicate — {existing} already tracks this alert. Skipping.")
            rows.append(f"| {repo} | {sev} | {rule_id} | duplicate of {existing} |")
            continue

        created = jira_request("POST", "/rest/api/3/issue", payload)
        key = created["key"]
        print(f"Created {key}: {JIRA_BASE_URL}/browse/{key}")
        rows.append(f"| {repo} | {sev} | {rule_id} | created [{key}]({JIRA_BASE_URL}/browse/{key}) |")
        slack_notify(key, alert, repo)

    write_summary(rows)


if __name__ == "__main__":
    main()
