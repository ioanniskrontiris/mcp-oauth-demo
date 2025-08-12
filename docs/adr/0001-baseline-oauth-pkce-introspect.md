# ADR 0001 — Baseline: OAuth 2.1 + PKCE + RS Introspection

## Context
We have an MCP-flavored demo: an Authorization Server (:9092), a Resource Server (:9091), and an AI-agent client that runs the Authorization Code + PKCE flow, receives an access token, and calls GET /tickets. The RS introspects tokens at the AS.

## Decision
Tag and branch a stable baseline before introducing a gateway:
- Branch: baseline/v0.1
- Tag: v0.1-baseline-oauth-mcp
- Feature flags scaffolded via .env (AUTH_MODE, TOKEN_MODE, INTROSPECTION_MODE, POLICY_MODE) with defaults that preserve current behavior.

## Consequences
- We can add a gateway that terminates raw tokens and mints internal assertions without breaking the direct path.
- Demos remain runnable with `AUTH_MODE=direct` at all times.
