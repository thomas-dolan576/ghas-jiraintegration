# Vuln → Jira Story Integration (VULN board)

Auto-creates a Jira Story in the **VULN** project when a code scanning (CodeQL) alert reaches the default branch, then posts a Slack alert telling the owner to clone the story to their home board.

Built to be fully testable **before the Jira service account exists** — the service account is a secrets-only swap.

## Layout

```
.github/workflows/vuln-jira-story.yml   # trigger + job
scripts/create_vuln_stories.py          # payload build, dedup, create, Slack (stdlib only)
fixtures/sample_alerts.json             # test alerts for workflow_dispatch
```

## How it triggers

- `code_scanning_alert` (types: `created`, `reopened`, `appeared_in_branch`) — fires only for alerts on the **default branch**, which is exactly "a vuln was merged to production."
- `workflow_dispatch` — manual test runs against `fixtures/sample_alerts.json`.

## Verified against the live VULN project (2026-07-16)

| Fact | Value |
| --- | --- |
| Project | `VULN` (id 17538, team-managed) |
| Story issue type id | `17745` |
| Required create fields | `project`, `issuetype`, `summary` (reporter defaults to auth user) |
| Priority field | **Not on the create screen** — severity is carried as `severity-<level>` label + description |
| Dedup mechanism | Label `gh-<org>-<repo>-alert-<n>` + JQL search before create |

## Test now (no service account, no credentials)

1. Commit this to a test repo.
2. Actions → "Vuln → Jira Story (VULN)" → Run workflow (defaults: fixture + `dry_run=true`).
3. Check the job summary for the payload table; exact JSON payloads are uploaded as the `jira-payloads` artifact.

## Test with real Jira (your personal token, before service account)

1. Create a personal API token: https://id.atlassian.com/manage-profile/security/api-tokens
2. Repo secrets: `JIRA_EMAIL` (your email), `JIRA_API_TOKEN`. Optional: `SLACK_WEBHOOK_URL`.
3. Run workflow with `dry_run=false` → real Stories appear on the VULN board (reporter = you).

## Go-live swap (when service account arrives)

1. Replace `JIRA_EMAIL` / `JIRA_API_TOKEN` secret values with the service account's.
2. Set repo/org variable `JIRA_DRY_RUN=false`.

No code changes.

## Notes / TODO

- CODEOWNERS matching in `suggest_owner()` is a simple last-match-wins approximation; swap in the audited matcher from `org_audit.py` for parity with the dashboard.
- For real trigger-path testing, seed a branch with a known CodeQL finding (e.g., an obvious SQL string concat) and merge it into a sandbox repo's default branch.
- Slack step uses an incoming webhook; if you want owner @-mentions, resolve CODEOWNERS teams → Slack user IDs via a lookup map.
- The `code_scanning_alert` event payload does not need `security-events: read` to read itself, but the permission is kept for future alert-API enrichment.
