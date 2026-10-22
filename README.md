# TrustVault

FastAPI secure document-sharing starter. Run: `pip install -r requirements.txt`, then `uvicorn app.main:app --reload`. Interactive docs: `/docs`.

## Demo credentials
- Admin: admin@example.test / Admin123!
- Owner: owner@example.test / Owner123!
- Viewer: viewer@example.test / Viewer123!

## Permissions
Owner controls their documents and grants/revoke read/edit access per named user. Viewer has no implicit access. Admin manages users/audit and can explicitly grant/delete but does not implicitly read file contents. Every document route checks the database server-side.

## API authorization
- POST /auth/token: public
- GET /auth/me: authenticated
- POST /documents: authenticated upload
- GET /documents: returns only owned/granted documents
- GET /documents/{id} and /download: owner or active grant
- PATCH /documents/{id}: owner or edit grant
- DELETE /documents/{id}: owner or admin
- PUT/DELETE /documents/{id}/grants/{user_id}: owner or admin
- GET /admin/users and /admin/audit: admin only

## Tests and deployment
Run `pytest`. Files are stored privately under UUID keys; downloads are authorized before the server opens the file. Revocation takes effect on the next request; already-downloaded copies cannot be recalled. For production use PostgreSQL, TLS, MFA, rate limits, malware scanning, encrypted storage, and an append-only audit service. `docker compose up --build` for a containerized demo.
