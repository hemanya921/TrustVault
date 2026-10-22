# TrustVault

FastAPI secure document-sharing prototype.

## Run locally

Install dependencies:

    python -m pip install -r requirements.txt

Start the server:

    python -m uvicorn app.main:app --reload

Open the interactive API documentation:

    http://127.0.0.1:8000/docs

## Demo credentials

These accounts are for synthetic demo data only.

- Admin: admin@example.test / Admin123!
- Owner: owner@example.test / Owner123!
- Viewer: viewer@example.test / Viewer123!

Do not use these passwords or the default signing secret for real confidential data.

## Permissions

Document owners control their own documents and grant or revoke named
users' read/edit permissions.

Viewers have no implicit access to other users' documents.

Administrators can inspect users and audit activity but do not
automatically receive document-content access.

The current grant/delete endpoints also contain administrator override
conditions. However, they first require ownership or an edit grant through
the shared authorization helper. Administrator status alone does not
bypass that initial check.

Every document route checks access on the server against current
database state.

## API authorization

- POST /auth/token: public login.
- GET /auth/me: authenticated users.
- POST /documents: authenticated upload.
- GET /documents: returns only owned or granted documents.
- GET /documents/{id}: owner or named read/edit grant.
- GET /documents/{id}/download: owner or named read/edit grant.
- PATCH /documents/{id}: owner or named edit grant.
- DELETE /documents/{id}: owner, or an administrator who also passes
  the initial edit-access check.
- PUT /documents/{id}/grants/{user_id}: owner, or an administrator
  who also passes the initial edit-access check.
- DELETE /documents/{id}/grants/{user_id}: owner, or an administrator
  who also passes the initial edit-access check.
- GET /admin/users: administrator only.
- GET /admin/audit: administrator only.

## Tests

Run:

    python -m pytest

The current tests cover cross-user metadata, download, edit, and delete
denial, plus download denial after permission revocation.

Broader security coverage and authorization mutation testing remain
unfinished.

## File storage and revocation

Files use server-generated UUID storage keys and are not served as
public static files.

Downloads check authorization before returning a file response.

Subsequent requests check current grants after revocation. Already
downloaded copies cannot be recalled. Cancellation of transfers already
in progress is not implemented.

## Current limitations

This is a prototype, not a production-ready or independently audited
document platform.

- Audit records are ordinary database rows, not immutable evidence.
- Denied authorization attempts are not centrally audited.
- Upload validation checks size and declared MIME type, not full
  file-content validation or malware scanning.
- Date-range search is not implemented.
- There is no dedicated document-management frontend; use /docs.
- MFA, login rate limiting, and server-side session revocation are
  not implemented.

See THREATS.md for accepted gaps and planned mitigations.

## Containerized demo

Run:

    docker compose up --build

Before deployment, configure a strong signing secret, HTTPS, persistent
database storage, private file storage, backups, and appropriate audit
protection. Do not upload real confidential documents to the public demo.