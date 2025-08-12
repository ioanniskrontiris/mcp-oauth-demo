# Gateway playground

This folder will host the identity-aware proxy that:
- validates user OAuth tokens (from AS)
- enforces policy (start with allow-all)
- mints short-lived internal *assertion JWTs*
- forwards to the RS with `Authorization: Bearer <assertion>`

We keep it isolated from the current demo; switch with AUTH_MODE=direct|gateway.
