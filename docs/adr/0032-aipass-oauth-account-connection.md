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
manufacture: a public OAuth client identifier must be supplied through
protected runtime configuration, and each deployed callback URI must be
registered for that client. The identifier is not an API key or client secret,
but its deployment value does not belong in source, logs, or application
responses. The feature must remain inert when either prerequisite is absent.

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
- Disconnect serializes with refresh and callback completion, deletes pending
  OAuth transactions, attempts refresh-token and access-token revocation
  independently, then unconditionally deletes local token material even if
  revocation or local decryption fails. A reconnect revokes the superseded
  grant after its replacement is durable. Account deletion uses the same path.

### Models and dispatch

- Discover models live with
  `GET https://aipass.one/oauth2/v1/models`, whose default response is the
  OpenAI list envelope (`{"object":"list","data":[...]}`). Ignore additive
  fields and accept the legacy string-array shape only as a migration fallback.
  Preserve accepted provider-prefixed model IDs exactly. When entries advertise
  a valid `methods` array, expose only `chat_completions` models. Lumen's
  existing 128-character ID and 256-character display-name bounds are local
  storage and UI safety limits, not claims about the AI Pass protocol. Do not
  add AI Pass model identifiers to a source-code allowlist.
- Revalidate a stored model against live discovery whenever it is selected or
  reactivated. Selecting AI Pass makes existing BYOK credentials inactive but
  leaves them connected; selecting BYOK makes AI Pass inactive. Existing
  platform and BYOK provider paths remain intact.
- Send wallet-backed chat to
  `POST https://aipass.one/oauth2/v1/chat/completions` through the server-owned
  provider. The initiation context carries only an opaque connection ID into a
  Celery turn; the worker obtains and refreshes the token inside its trust
  boundary.
- Only tutor context resolution opts into AI Pass. Authoring, course building,
  learning-path generation, background work, and all existing provider paths
  keep their prior platform/BYOK behavior. This keeps wallet-backed work on the
  surface whose stop action durably aborts the active upstream request.
- Streamed tutor jobs retain the opaque AI Pass connection ID after
  disconnect. A worker that starts later therefore fails closed on the missing
  grant instead of losing the funding marker and falling through to platform
  billing.
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
- Validate callback query bounds inside the redirect handler so malformed
  authorization codes or state are never reflected by framework validation
  responses. Scrub AI Pass transport locals from error telemetry.
- Ship behind `FEATURE_AIPASS_OAUTH_ENABLED=false`. If the configured public
  client identifier, registered callback URI, or secure KEK is absent, fail
  closed and show the account connection as unavailable.
- Keep upstream source blank and configurable. A fork-owned private preview may
  inject an AI Pass-owned evaluation client identifier through repository
  secrets only for a callback already registered to that client. It must never
  become an upstream default or be committed, printed, logged, or returned.
  Maintainer deployments replace it through the same
  `AIPASS_OAUTH_CLIENT_ID` variable with a maintainer-owned registration.

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
- **A client secret** — rejected: this is a public client and uses PKCE;
  shipping a secret with a public-client integration would be misleading.
- **Rendering stop locally while the worker continues** — rejected: the user
  would continue funding work after cancellation.

## Consequences

- API and worker processes both remain inside the encrypted-token trust
  boundary and require the same KEK versions.
- The existing KEK rotation command covers AI Pass token bundles and pending
  PKCE verifiers as well as BYOK credentials before an old KEK is retired.
- The feature is deployable only after operators provide a public client
  identifier through protected runtime configuration and register the exact
  HTTPS callback URI. Until then it is intentionally unavailable.
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
