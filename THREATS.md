# Threat model

## Mitigations
- IDOR: all document routes call `authorized_document`, checking ownership/current grants server-side.
- Revocation: no signed file URLs; each download re-checks grants. Already-downloaded copies remain.
- Path traversal: client filenames are not used as paths; storage keys are UUID hex.
- Roles: admin does not implicitly receive document-content access.
- Inactive accounts are rejected on every request.
- Upload size cap and MIME allowlist.

## Accepted gaps
- Audit rows are not cryptographically immutable; a DB administrator can alter them. Production needs append-only/WORM audit storage and hash chaining.
- MIME type is client-supplied; add signature validation and malware scanning.
- No MFA, password reset, rate limiting, or token revocation.
- SQLite is demo-only; use PostgreSQL in production.
- No encryption-at-rest implementation, versioning, external sharing, folders, retention, or recovery.
- Denied authorization attempts are not centrally audited yet.
