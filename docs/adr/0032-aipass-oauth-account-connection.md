# ADR-0032: Optional AI Pass OAuth account connection

- **Status:** Proposed
- **Date:** 2026-07-25
- **Deciders:** project maintainers

## Context

Lumen already supports platform-funded model calls and optional BYOK
credentials. AI Pass is a different product shape: a learner connects an
account and spends from that account's shared AI Pass wallet. It must not be
presented or implemented as another API-key field.

Lumen is a server-backed web application. The browser therefore cannot safely
own OAuth bearer tokens or authenticated AI Pass transport. The FastAPI API and
Celery worker are already the trust boundary for encrypted BYOK credentials and
foreground LLM dispatch, so they are also the strongest available place for AI
Pass OAuth material and wallet-billed requests.

The integration also has deployment prerequisites that this repository cannot
manufacture: the existing first-party public client identifier must be supplied
through protected runtime configuration, and each deployed callback URI must be
registered for that client. No client identifier value belongs in source
control. The feature must remain inert when either prerequisite is absent.

## Decision

### Authorization and browser binding

- Use OAuth 2.0 Authorization Code with PKCE S256 as a public client. There is
  no client secret.
- Resolve and strictly validate authorization, token, userinfo, and revocation
  endpoints from
  `https://aipass.one/.well-known/oauth-authorization-server`. Discovery must
  advertise authorization-code and refresh grants, S256, and token endpoint
  authentication method `none`; resolved endpoints must remain HTTPS on
  `aipass.one`.
- Generate independent high-entropy state, PKCE verifier, and browser-link
  nonce values. Store only hashes of state and browser nonce. Store the verifier
  encrypted server-side, expire the transaction after ten minutes by default,
  and consume it before exchanging the code so a failed exchange cannot be
  replayed.
- Bind the callback to the initiating browser with a short-lived HttpOnly,
  SameSite=Lax cookie (`__Host-aipass-link` and Secure in production). The
  callback does not depend on Lumen's SameSite=Strict login cookie, which is not
  sent after the cross-site authorization redirect.
- Use the configured public client identifier only in the OAuth protocol
  requests. Do not return it in application JSON, persist it in ordinary
  configuration tables, or include it in logs, errors, telemetry, or source.

### Token and identity storage

- Keep access tokens, refresh tokens, and PKCE verifiers exclusively in
  server-side envelope-encrypted Postgres columns backed by Lumen's versioned
  KEK. The production boot guard treats these rows as encrypted-secret rows and
  refuses an unsafe KEK configuration.
- Persist only a SHA-256 hash of the AI Pass subject. Do not persist userinfo
  email or profile payloads.
- Return only connection status, selected model, and active state to browser
  code. Bearer tokens never enter React state, browser storage, query caches, or
  client-visible error payloads.
- Refresh under a row lock in an independent short transaction and replace the
  encrypted bundle in the same commit. A failed refresh marks the connection
  `reauth_required` and inactive.
- Disconnect attempts refresh-token and access-token revocation independently,
  then unconditionally deletes local token material even if revocation or local
  decryption fails. Account deletion uses the same disconnect path.

### Models and dispatch

- Discover models live with
  `GET https://aipass.one/oauth2/v1/models?detailed=true`. Accept the OpenAI
  list envelope (`{"object":"list","data":[...]}`) and the legacy string-array
  shape defensively. Do not add AI Pass model identifiers to a source-code
  allowlist.
- Revalidate a stored model against live discovery whenever it is selected or
  reactivated. Selecting AI Pass makes existing BYOK credentials inactive but
  leaves them connected; selecting BYOK makes AI Pass inactive. Existing
  platform and BYOK provider paths remain intact.
- Send wallet-backed chat to
  `POST https://aipass.one/oauth2/v1/chat/completions` through the server-owned
  provider. The initiation context carries only an opaque connection ID into a
  Celery turn; the worker obtains and refreshes the token inside its trust
  boundary.
- Record `billing_mode="aipass"` separately from platform and BYOK. AI Pass
  remains subject to non-dollar request/concurrency safeguards but does not
  consume Lumen's platform-dollar budget.
- Poll the durable turn status during streaming. When the API marks a turn
  aborted, cancel the worker task; cancellation propagates into the active
  HTTP response context and closes the upstream stream so wallet-billed work is
  stopped, not merely hidden from the UI.

### Bounds and failure behavior

- Bound request bodies, JSON responses, SSE event size, total streamed bytes,
  token/model field sizes, and OAuth transaction lifetime.
- Apply connect rate limiting and hard timeouts to discovery, token, userinfo,
  model, revoke, and chat traffic. Follow no redirects.
- Normalize upstream failures without response bodies, tokens, authorization
  codes, state, vendor request IDs, or headers in client-visible errors.
- Ship behind `FEATURE_AIPASS_OAUTH_ENABLED=false`. If the protected public
  client identifier, registered callback URI, or secure KEK is absent, fail
  closed and show the account connection as unavailable.

## Alternatives considered

- **An AI Pass API-key field** — rejected: account connection and shared-wallet
  authorization are the required product and security model.
- **Tokens in browser JavaScript or browser storage** — rejected: Lumen has a
  server trust boundary, so exposing bearer material to the webview needlessly
  expands the compromise surface.
- **A backend-for-frontend token exchange followed by browser chat** —
  rejected: it still exposes bearer material and makes browser cancellation
  unreliable for upstream wallet spend.
- **Hard-coded AI Pass models** — rejected: the catalog is live account data
  and can change independently of Lumen.
- **A client secret** — rejected: this is an existing public client and uses
  PKCE; shipping a secret with a public-client integration would be misleading.
- **Rendering stop locally while the worker continues** — rejected: the user
  would continue funding work after cancellation.

## Consequences

- API and worker processes both remain inside the encrypted-token trust
  boundary and require the same KEK versions.
- The feature is deployable only after operators provide the existing public
  client identifier through protected runtime configuration and register the
  exact HTTPS callback URI. Until then it is intentionally unavailable.
- Live end-to-end authorization cannot be represented by repository fixtures.
  Automated coverage uses sentinel credentials and mocked AI Pass transport;
  deployment still requires the manual authorization, refresh, model, chat,
  cancellation, and revocation checklist.
- Two small tables and one nullable tutor-turn foreign key are added by
  migration 0054. Disabling the feature preserves all existing provider paths
  and leaves no AI Pass UI capable of initiating transport.

## References

- AI Pass OAuth authorization-server metadata:
  `https://aipass.one/.well-known/oauth-authorization-server`
- OAuth 2.0 for native/public apps: RFC 8252
- PKCE: RFC 7636
- Token revocation: RFC 7009
- ADR-0027: BYOK model configuration and server-side secret storage
