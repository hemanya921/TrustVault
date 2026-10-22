# AI work log

> Replace these starter entries with real dated prompts, outputs, failures, fixes, and commit links as you build. At least two entries must concern authorization or audit integrity.

## Reusable context
Build a small secure document-sharing API. Authorization must be server-side and per request. Never expose raw file paths or public object URLs. Be honest about limitations.

## 2026-10-22 — Authorization scaffold
- Asked: create per-document grants and protected download route.
- Produced: shared `authorized_document` helper.
- Risk: routes could return data before checking grants.
- Fix: review every route and add cross-user HTTP tests. Commit: REPLACE_WITH_REAL_COMMIT.

## 2026-10-22 — Revocation
- Asked: design immediate revocation.
- Produced: DB-backed grants checked during download.
- Risk: signed/cached URLs would outlive revocation.
- Fix: no such URLs; test download before/after revoke. Commit: REPLACE_WITH_REAL_COMMIT.

## 2026-10-22 — Audit integrity
- Asked: add audit trail.
- Produced: audit rows in same DB.
- Risk: not tamper-proof; denied attempts not centrally logged.
- Fix: document gap; propose append-only external audit store. Commit: REPLACE_WITH_REAL_COMMIT.

## 2026-10-22 — Upload validation
- Asked: validate uploads and keep storage private.
- Produced: MIME allowlist, size cap, UUID keys.
- Risk: MIME is spoofable.
- Fix: document signature validation and AV scanning as production requirements. Commit: REPLACE_WITH_REAL_COMMIT.

## 2026-10-22 — Security tests
- Asked: prove one user cannot access another’s document.
- Produced: tests for metadata/download/edit/delete and revocation.
- Risk: tests must fail if authorization is removed.
- Fix: mutation-test by bypassing `authorized_document` and confirm failures. Commit: REPLACE_WITH_REAL_COMMIT.
