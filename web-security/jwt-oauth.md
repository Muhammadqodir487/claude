# JWT & OAuth/OIDC Attacks

## Summary
JWT vulnerabilities are almost always implementation bugs in how a
library/app *validates* a token, not cryptographic breaks of the
algorithms themselves. OAuth/OIDC vulnerabilities are almost always
*flow logic* bugs (confused deputy, missing state/PKCE, redirect_uri
laxness) rather than protocol-level flaws. The two are frequently chained
because OIDC uses JWTs as its id_token.

## Root Cause
- JWT: library trusts attacker-controlled fields in the token header
  (`alg`, `kid`, `jku`, `x5u`) to decide *how* to verify the signature,
  or fails to enforce that the verification algorithm matches what the
  issuer intended.
- OAuth/OIDC: the authorization server or client trusts attacker-supplied
  values (`redirect_uri`, `state`, `client_id`) without strict matching,
  or the client fails to bind the authorization code/token to the
  session that initiated the flow.

## Attack Flow (JWT)
1. Decode the token (base64url, three dot-separated parts) and inspect
   the header for `alg`, `kid`, `jku`, `x5u`, `x5c`.
2. Determine what the server does when these are manipulated.
3. Forge a token with attacker-chosen claims, signed in a way the server
   will accept.

## Exploitation (JWT)
- **`alg: none`**: strip the signature, set `alg` to `none`/`None`/`NONE`
  (case variants sometimes bypass a naive check), submit token with empty
  signature segment. Works when the library treats "none" as valid rather
  than rejecting unless explicitly allowed.
- **RS256 → HS256 algorithm confusion**: if the server has an RSA public
  key it uses to verify RS256 tokens, and the verification code does
  `verify(token, key)` without pinning the expected algorithm, an
  attacker can craft an HS256 token *signed using the RSA public key
  (which is not secret) as the HMAC secret*. The server, expecting to
  verify signature generically, computes HMAC-SHA256 with that same
  public key string and it matches — full forgery.
- **`kid` (Key ID) injection**: if `kid` is used to look up a key from a
  filesystem path, DB, or JWKS URL without sanitization:
  - Path traversal: `kid: "../../../../dev/null"` → verify against an
    empty/known key (e.g., HMAC with empty string as secret if paired
    with alg confusion).
  - SQL injection via `kid` if it's used in a raw DB lookup query.
  - `jku`/`x5u` **SSRF + spoofing**: point the "JWK Set URL" or
    "X.509 URL" header at an attacker-controlled server serving a key the
    attacker generated — the server fetches it and verifies the
    attacker's own forged signature against the attacker's own key.
- **Weak HMAC secret**: brute-force with `hashcat -m 16500` or
  `jwt_tool`/`jwt-cracker` against common/short secrets.
- **Missing signature verification entirely**: some libraries/frameworks
  historically decoded-but-didn't-verify by default (older
  `jsonwebtoken` misuse, `jwt.decode()` vs `jwt.verify()` confusion in
  Node).
- **Claim tampering when signature isn't actually checked end-to-end**:
  e.g., API gateway validates the JWT and strips it, but a downstream
  microservice re-trusts a *different*, attacker-controllable header
  (`X-User-Id`) that was supposed to be set from the validated claims —
  classic gateway/microservice trust boundary bug (also see: this
  session's Vodafone Oman program explicitly listing "JWT in ajax
  requests ignores path and HTTP method" as an out-of-scope finding
  class — i.e., a *known* weak spot they've already accepted risk on).
- **`exp`/`nbf` not enforced**: replay an old, "expired" token because
  the server never checks the claim.

## Attack Flow / Exploitation (OAuth/OIDC)
- **`redirect_uri` manipulation**: if validation is substring/prefix-based
  rather than exact-match, register
  `https://legit-client.com.attacker.com` or
  `https://legit-client.com/callback/../../../attacker-path`, or exploit
  open redirects *on the legitimate client* as a valid `redirect_uri`
  (authorization code lands on attacker-controlled page via the client's
  own open redirect).
- **Missing/predictable `state`**: CSRF the OAuth flow — attacker
  initiates login with their own account, captures the callback, replays
  it into the victim's browser, linking the *victim's* session to the
  *attacker's* third-party account (login CSRF / account linking
  confusion) or vice versa.
- **Authorization code injection (no PKCE)**: attacker obtains a valid
  authorization code for their own flow, injects it into the victim's
  browser session at the client's callback endpoint — if the client
  doesn't bind the code to the session/state that started the flow, the
  victim's session gets upgraded using the attacker's identity (or the
  reverse, depending on direction) — this is precisely why PKCE
  (`code_verifier`/`code_challenge`) exists.
- **Mix-up attack** (multiple IdPs): client doesn't verify which
  authorization server actually issued the code/token, attacker
  redirects the flow through a malicious "IdP" they control while
  reusing a legitimate client_id.
- **Scope escalation**: client requests broad scope silently approved by
  session-based "remembered consent," or the token endpoint doesn't
  re-validate that the granted scope matches what was originally
  consented to.
- **Client secret exposure**: mobile/SPA apps shipping a "confidential
  client" secret — extractable from the app binary, enabling full
  impersonation of the OAuth client itself.
- **Confused deputy via `id_token` as access token**: an OIDC id_token is
  meant for the *client* to authenticate the user, not as a bearer token
  against APIs; apps that pass the id_token straight through to a
  resource server which is a different audience (`aud`) than intended
  open cross-app replay if `aud` isn't checked.

## Bypass
- Case/format variations on `alg` (`None`, `NoNe`) against naive
  string-equality checks.
- Testing every one of `kid`/`jku`/`x5u`/`x5c` even if only one is
  documented as "the" vulnerable header in a given library version —
  implementations vary in which they honor.
- For `redirect_uri`: try trailing slash differences, `%2e%2e/`,
  case-changes on the host, adding a fragment, adding extra query
  params the validator might not canonicalize before comparing.

## Automation
- `jwt_tool` (automates alg=none, alg confusion, kid injection, common
  secret brute force, claim fuzzing).
- Burp's "JWT Editor" extension for manual header/claim manipulation
  with re-signing helpers (generate RSA/HMAC key pairs on the fly).
- For OAuth flow logic bugs there's no good "automated scanner" — this is
  fundamentally a state-machine/logic-review task: map every step of the
  flow, and at each step ask "what does the server actually verify
  here, versus what does it merely trust from the previous step?"

## Detection
- Log and alert on `alg` header values other than the one expected token
  type should always be issued with.
- Monitor for anomalous `kid` values (path-traversal-looking strings,
  SQL metacharacters).
- Rate-limit and alert on OAuth callback requests with mismatched/replayed
  `state` or `code` values.

## Mitigation
- Pin the expected algorithm explicitly in verification calls — never
  trust `alg` from the token to select the verification method.
- Use separate key material / library configuration for RS256 vs HS256
  so algorithm confusion is structurally impossible.
- Validate `kid` against an allowlist of known key IDs; never use it in a
  raw file path or SQL query.
- Always implement PKCE, even for confidential clients (OAuth 2.1 makes
  this mandatory).
- Exact-match `redirect_uri` validation against a pre-registered
  allowlist — no substring/prefix matching, no wildcards beyond what's
  strictly necessary.
- Always validate `aud` (audience) and `iss` (issuer) claims on every
  token, at every service that consumes it — not just at the perimeter.

## Variant Hunting
- Any service that issues its *own* JWTs downstream of a validated OIDC
  session (internal service-to-service tokens) — check if the same
  alg-confusion/kid-injection bugs were reintroduced in that in-house
  implementation, since teams often hand-roll a "simpler" internal JWT
  library that skips hardening the original library had.
- Check every OAuth "connect your X account" integration separately —
  each third-party integration often re-implements its own OAuth client
  logic with independent redirect_uri/state handling bugs, even within
  the same product.

## Related CVEs
- CVE-2015-9235 (node-jsonwebtoken alg confusion, the canonical
  RS256→HS256 bug write-up origin)
- CVE-2016-5431 / CVE-2016-10555 (various JWT library alg=none handling)
- CVE-2018-0114 (`jwt-simple` npm — signature bypass)

## Related Bug Bounty Reports
- Numerous H1 reports across SSO providers for `redirect_uri` bypass via
  open-redirect chaining on the client application.
- PayPal OAuth account-takeover-class reports (missing state parameter,
  historical).

## Related Research
- Auth0 / Okta engineering blogs on JWT "none" algorithm and alg
  confusion.
- "OAuth 2.0 Security Best Current Practice" (IETF draft) — canonical
  reference for every mitigation listed above, written specifically in
  response to real-world attack classes.
- PortSwigger Web Security Academy — JWT and OAuth chapters (excellent
  hands-on labs for each bypass class above).

## Practical Hunting Tips
- Always decode every JWT you see in a target (headers, cookies, local
  storage) even if it "looks internal" — internal-service JWTs are
  frequently less hardened than the customer-facing login JWT.
- For OAuth: literally draw the sequence diagram of the flow (who sends
  what, what does each party verify) before trying anything — most real
  bugs are found by noticing a verification step that's *implied* but
  never actually implemented, not by guessing payloads.

## Real World Examples
- This session's Vodafone Oman engagement explicitly listed "JWT in ajax
  requests ignores path and HTTP method" in their **out-of-scope** list —
  a useful real-world signal that programs sometimes pre-emptively
  exclude known-but-accepted-risk JWT scoping weaknesses; always read a
  program's out-of-scope list closely, since it often reveals exactly
  which vulnerability classes they've already found internally.

## References
- https://portswigger.net/web-security/jwt
- https://portswigger.net/web-security/oauth
- RFC 6749 (OAuth 2.0), RFC 7636 (PKCE), RFC 9700 (OAuth 2.0 Security BCP)
