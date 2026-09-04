# GraphQL Security

## Summary
GraphQL's flexibility — a single endpoint, client-specified queries, a
self-describing schema — inverts several REST-era assumptions security
tooling and reviewers are used to. The recurring theme across nearly
every GraphQL vulnerability class: authorization and complexity/rate
controls that were designed with "one query = one HTTP request" in mind
silently stop applying once queries can be aliased, batched, nested, or
sent over a *different* transport (WebSocket subscriptions) than the one
those controls were actually wired into.

## Root Cause
- **Introspection left enabled in production** exposes the entire schema
  (types, fields, mutations, deprecated-but-still-live fields) to an
  unauthenticated attacker — turns blind recon into a complete API map
  handed over for free.
- **Authorization checked at the request level, not the resolver
  level**: middleware that validates "is this caller authenticated/
  authorized" once per HTTP request breaks down the moment a single
  request can contain many independent queries (aliasing, batching) —
  some implementations only check auth against the *first* query in a
  batch, silently trusting the rest.
- **Transport-specific middleware gaps**: authentication, introspection
  control, and query-complexity limits are frequently implemented as
  HTTP middleware wired into the REST-style request pipeline — a
  GraphQL subscription server listening on WebSocket is a *different*
  code path that can bypass all of it if not independently re-
  implemented, not merely reused.
- **BOLA/IDOR and BFLA translate directly from REST** — GraphQL doesn't
  introduce a new root cause for these, just a new place (individual
  resolvers, not URL routes) where the same missing per-object/per-
  function authorization check has to be re-verified.

## Attack Flow
1. Check whether introspection is enabled (`{__schema{types{name}}}` or
   equivalent); if disabled, fall back to field-suggestion errors
   (typo'd field names often trigger "did you mean X" responses that
   leak schema fragments) or a wordlist-based schema reconstruction.
2. Map every mutation and query resolver to the object/data it touches,
   specifically flagging anything that looks like it should require
   ownership/role checks (update, delete, admin-prefixed operations).
3. Test authorization per-resolver, not just per-endpoint: authenticate
   as a low-privilege user and attempt every sensitive query/mutation
   directly, including ones not exposed in the client application's own
   UI (schema access means every resolver is reachable regardless of
   what the frontend actually calls).
4. Test batching/aliasing behavior specifically: send a batch mixing an
   authenticated-looking query with additional aliased queries, and a
   request with many aliased copies of an expensive query, to probe
   both the auth-bypass and DoS surfaces at once.
5. If the API exposes subscriptions, test the WebSocket endpoint as an
   entirely separate attack surface — do not assume HTTP-endpoint
   findings (or fixes) carry over to it.

## Exploitation
- **Batching/aliasing auth bypass**: authenticated and unauthenticated
  queries mixed in a single request, exploiting middleware that only
  validates the request as a whole (or only its first query) rather than
  each aliased/batched query independently.
- **Query depth/complexity DoS**: deeply nested or aliased queries that
  fan out into an enormous number of resolver calls/database queries
  from a single small HTTP request — classic "one request, N backend
  operations" amplification.
- **CVE-2026-32594 (Parse Server, CVSS 6.9)**: the GraphQL WebSocket
  subscription endpoint didn't pass through the Express middleware chain
  enforcing authentication, introspection control, and complexity
  limits — an attacker could connect directly to the WebSocket, execute
  operations without any API key, pull the full schema via introspection
  even when disabled over HTTP, and send arbitrarily complex queries
  bypassing configured limits entirely. Fixed in 8.6.40 / 9.6.0-alpha.14.
- **Subscription auth bypass via unverified JWT (@neo4j/graphql)**:
  subscription `connectionParams.jwt` accepted without verification —
  the same transport-specific-gap root cause as the Parse Server case,
  in a different GraphQL library, confirming this is a systemic pattern
  across implementations rather than one project's bug.
- **Shopify IDOR (HackerOne #2207248, $5,000 bounty)**: BOLA on the
  `BillingDocumentDownload` and `BillDetails` GraphQL queries — a
  standard object-level authorization miss, notable mainly for
  confirming this bug class pays at scale on mature, heavily-reviewed
  GraphQL APIs.

## Bypass
- Introspection-disabled APIs are frequently still enumerable via error-
  message field suggestions or by trying a curated wordlist of common
  field/type names against the schema's actual behavior (valid vs.
  "field does not exist" responses).
- Persisted-query allowlists (meant to restrict clients to a fixed set
  of pre-approved queries) can be bypassed if the server doesn't
  strictly reject any query not matching a known persisted-query hash —
  test sending a raw, non-persisted query directly rather than assuming
  the allowlist is actually enforced server-side.
- CORS/CSRF controls tuned for the REST era don't automatically cover a
  GraphQL endpoint that accepts state-changing mutations over a simple
  `GET` or unauthenticated cross-origin `POST` — test CSRF against
  mutations specifically, not just queries.

## Automation
- Schema-driven fuzzing: once introspection (or a reconstructed schema)
  is available, auto-generate a test matrix covering every mutation
  under a low-privilege identity — this scales far better than manually
  picking "interesting-looking" resolvers.
- Batching/aliasing probes: script systematic generation of aliased-
  query batches at increasing depth/count to find both the authorization
  boundary and the complexity-limit boundary in one pass.

## Detection
- Log and alert on introspection queries from non-development network
  ranges/identities — legitimate clients rarely need runtime
  introspection in production.
- Monitor for anomalous batch size/query depth/aliasing count relative
  to a baseline of what legitimate client applications actually send —
  a hand-crafted client can trivially exceed what any real frontend
  would ever generate.

## Mitigation
- Disable introspection in production; if internal tooling needs it,
  gate it behind its own authentication, separate from the public API
  surface.
- Enforce authorization per-resolver (field-level), not per-request —
  treat every resolver as an independent authorization boundary the way
  every REST route would be.
- Implement query cost analysis / depth limiting server-side, and verify
  it's wired into *every* transport the schema is served over
  (HTTP and WebSocket both) rather than assuming one implementation
  covers both.
- Explicitly test and harden the subscription/WebSocket code path as its
  own surface — per CVE-2026-32594 and the neo4j/graphql advisory, this
  is where auth/complexity controls most often go missing by omission
  rather than by a specific bug.

## Variant Hunting
- Any GraphQL server offering subscriptions is worth a dedicated pass
  checking whether auth/introspection/complexity middleware actually
  applies to the WebSocket path — this exact gap has now recurred across
  at least two independent GraphQL implementations (Parse Server,
  neo4j/graphql), suggesting it's a common integration mistake rather
  than one-off carelessness.
- For any BOLA/IDOR found on one query/mutation, check every other
  resolver touching the same underlying object type — GraphQL schemas
  frequently expose the same entity through multiple query paths
  (direct query, nested field on a parent type, admin-prefixed variant)
  that each need their own authorization check independently verified.

## Related CVEs
- CVE-2026-32594 — Parse Server, CVSS 6.9, GraphQL WebSocket
  subscription endpoint bypassing auth/introspection/complexity
  middleware.
- @neo4j/graphql advisory (GHSA-fcpg-3fw5-vc65) — subscription auth
  bypass via unverified `connectionParams.jwt`.

## Related Bug Bounty Reports
- Shopify / HackerOne #2207248 — $5,000, IDOR on
  `BillingDocumentDownload`/`BillDetails` GraphQL queries.

## Related Research
- RingSafe — "GraphQL Security 2026 — Beyond Introspection."
- StingRAI — "GraphQL API Vulnerabilities, Attacks & CVEs (2026)."

## Practical Hunting Tips
- Always test the subscription/WebSocket endpoint as a separate target
  from the main HTTP GraphQL endpoint, even (especially) when the HTTP
  endpoint looks well-secured — the 2026 pattern strongly suggests teams
  secure the HTTP path and forget the WebSocket path exists.
- When introspection is disabled, don't stop — field-suggestion error
  messages and a curated common-field wordlist frequently reconstruct
  enough of the schema to proceed with resolver-level authorization
  testing regardless.

## Real World Examples
- CVE-2026-32594 (Parse Server) — WebSocket subscription auth/
  introspection/complexity-limit bypass.
- Shopify HackerOne #2207248 — $5,000 BOLA/IDOR on billing-related
  GraphQL queries.

## References
- https://radar.offseq.com/threat/cve-2026-32594-cwe-306-missing-authentication-for--2bea7820
- https://github.com/neo4j/graphql/security/advisories/GHSA-fcpg-3fw5-vc65
- https://ringsafe.in/graphql-security-beyond-introspection/
- https://www.stingrai.io/blog/graphql-api-vulnerabilities-and-common-attacks

---
*Added 2026-09-04 via research pass.*
