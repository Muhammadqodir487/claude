# Broken Access Control / BOLA / IDOR

## Summary
The single most-reported category across both classic web bug bounty
and the OWASP API Security Top 10 (BOLA/IDOR sits at API1, effectively
unchanged in rank across the 2019 and 2023 editions, still current as of
2026), and one of the highest ROI categories for a hunter: it's a logic
flaw, not a coding-syntax error — the server correctly confirms *who you
are* (authentication) but fails to confirm *whether you're allowed to
touch this specific object or perform this specific action*
(authorization). The renaming from "IDOR" to "BOLA" in OWASP's own
taxonomy is itself informative: it shifts the framing from "the ID was
guessable" (an implementation detail) to "the authorization check was
missing" (the actual root cause) — guessable IDs are just the most common
way the missing check gets discovered, not the vulnerability itself.

## Root Cause
- **Missing or incomplete per-object authorization check**: an endpoint
  authenticates the caller, then fetches/modifies an object by an
  ID supplied in the request, without separately verifying that *this*
  caller owns or is permitted to act on *that specific* object ID.
- **Authorization checked at the wrong granularity**: a check that
  confirms "is this user logged in" or "does this user have role X" but
  never checks "does this user own object #4821 specifically" — role-
  level (BFLA, Broken Function-Level Authorization) and object-level
  (BOLA) checks are frequently conflated, and passing one is wrongly
  treated as sufficient for the other.
- **Direction-of-check asymmetry**: a resource might correctly restrict
  *reads* to the owner but forget to apply the same restriction to
  *writes* (or vice versa) on the same object — the two check paths were
  implemented separately and drifted.
- **Action-level blind spots**: per the largest current empirical
  study of disclosed BOLA reports, the single largest confirmed
  category (41.7% of cases) is **Action-Level Object BOLA** — unauthorized
  *state-changing actions* on another user's object (not just reading
  their data) — meaning teams that only defensively review "can user A
  read user B's data" and stop there are missing the plurality of
  real-world BOLA impact, which is about *doing things* to someone
  else's object, not just viewing it.

## Attack Flow
1. Walk the entire application once as an authenticated low-privilege
   test user, capturing every request (proxy history).
2. Replay every captured request under a *second* low-privilege test
   account's session, changing only the object identifier(s) to point
   at the first account's objects, and diff the responses — any request
   that "succeeds" under the wrong account's session (returns data,
   performs the action, or returns a subtly different error than a
   genuinely-nonexistent-object request) is a candidate finding.
3. Don't stop at objects visible in the UI — enumerate hidden/
   admin-only endpoints and API routes not exposed in the primary
   client application; BOLA frequently exists on endpoints the UI never
   calls for a given role but the backend never actually gated.
4. Test both directions explicitly (read *and* write/delete/update) for
   every object type found, since the drift pattern above means a fixed
   read-path doesn't imply a fixed write-path on the same object.
5. Test mass-assignment alongside BOLA on the same requests: does an
   update endpoint accept and persist fields the client shouldn't be
   able to set (role, ownerId, price, isAdmin), independent of whether
   object-ownership is itself correctly checked.

## Exploitation
- **Uber Eats BOLA/IDOR ($2,000 bounty)**: unauthorized access to
  another user's order/account data by manipulating an object identifier
  in an Uber Eats API request — a representative example of the
  "walk the app, swap the ID, diff the response" methodology yielding a
  paid finding on a mature, heavily-tested target.
- **Action-Level Object BOLA (41.7% of confirmed cases per the 2026
  empirical taxonomy)**: unauthorized state-changing actions — e.g.,
  canceling, modifying, or deleting another user's order/resource/
  subscription — rather than merely reading their data. This is the
  dominant real-world pattern and the one most likely to be missed by
  testing that only checks "can I read someone else's stuff."
- **Direct Object Reference BOLA**: the classic case, and (alongside
  Action-Level) one of the two dominant families in the same empirical
  dataset — sequential/predictable/guessable identifiers directly
  exposed in a URL or API parameter with no ownership check at all.

## Bypass
- **ID obfuscation is not a fix**: switching from sequential integers to
  UUIDs or hashed IDs raises the difficulty of *guessing* an ID but does
  nothing for the actual missing-authorization-check root cause if the
  attacker can *observe* a valid ID belonging to another user through
  any other channel (a shared resource listing, a referral link, an
  export feature, a webhook payload) — treat obfuscated IDs found this
  way exactly like predictable ones for testing purposes.
- **Testing only the primary client-exposed endpoints misses backend-
  only routes** that enforce authorization inconsistently (or not at
  all) relative to the routes the frontend actually calls — API
  documentation/schema discovery (GraphQL introspection, OpenAPI specs,
  JS bundle analysis for hardcoded API paths) routinely surfaces these.
- **Partial fixes that check ownership on the "parent" object but not a
  nested "child" object** — e.g., correctly verifying the requesting
  user owns order #123, but then not separately verifying they own line-
  item #456 *within* an arbitrary order ID supplied alongside it.

## Automation
- **Autorize / Auth Analyzer** (Burp extensions) — automatically replay
  every request made under one session using a second, lower-privileged
  session's credentials, and flag responses that "succeed" when they
  shouldn't — converts single-pass manual app walking into full-coverage
  BOLA testing without manually re-issuing every request twice.
- Script systematic ID-swapping across every captured request
  (sequential increment/decrement plus a small set of known other-
  account object IDs) as a batch pass once initial manual testing
  confirms the general pattern is worth pursuing at scale on a given
  target.

## Detection
- Log and alert on any request where the authenticated user's ID
  doesn't match the owner of the object ID being accessed/modified in
  the request — this is directly detectable from application-level
  access logs if object ownership is recorded, independent of whether
  the request "succeeded" from the attacker's perspective.
- Monitor for abnormal sequential-ID access patterns (one account
  querying many different object IDs in a short window) as a behavioral
  signal of active BOLA enumeration, distinct from content-based
  detection.

## Mitigation
- Enforce object-level authorization as a mandatory, centralized check
  on every data-access/mutation path (a shared middleware/decorator
  pattern applied uniformly), rather than re-implementing an ownership
  check ad hoc per endpoint — the drift pattern (fixed on read, missed
  on write) is exactly what centralizing the check eliminates.
- Explicitly test and gate **every** state-changing action per object,
  not just read access — given that Action-Level BOLA is the dominant
  real-world category, teams that only reviewed read-paths for
  authorization are missing the majority of actual risk.
- Never treat identifier obfuscation (UUIDs, hashes) as a substitute for
  an actual authorization check — it raises attacker cost for pure
  guessing but does nothing against any identifier-disclosure channel.

## Variant Hunting
- For every object type where a read-path BOLA was found and fixed,
  explicitly re-test every write/update/delete path on the *same*
  object type — per the empirical data, this is where the majority of
  remaining risk actually lives after an initial read-path fix.
- Re-test nested/child-object relationships specifically: a correctly-
  gated parent object with an un-gated child-object parameter
  underneath it is a systematic, repeatable pattern across many
  different applications' data models.
- Any endpoint reachable only via schema discovery (GraphQL
  introspection, OpenAPI spec, JS bundle route extraction) rather than
  the primary UI flow is worth a dedicated BOLA pass — these are
  disproportionately likely to have been overlooked during the
  application's own internal security review, which tends to focus on
  UI-exposed flows.

## Related CVEs
- (BOLA/IDOR findings are overwhelmingly disclosed as bug-bounty reports
  rather than assigned CVEs, since they're application-specific logic
  flaws rather than product vulnerabilities — populate specific
  CVE-tracked product cases here if found, e.g. in widely-deployed
  SaaS/CMS platforms.)

## Related Bug Bounty Reports
- Uber Eats BOLA/IDOR — $2,000, unauthorized access via object
  identifier manipulation.
- Broader empirical dataset: 84 of 107 classified HackerOne
  IDOR/Improper-Access-Control disclosures (2021-2026) confirmed as
  in-scope BOLA — useful as a base rate for how often this tag
  corresponds to a "real" BOLA vs. a mis-tagged or out-of-scope report.

## Related Research
- "Broken Object Level Authorization in the Wild: An Empirical Taxonomy
  from 100+ Bug Bounty Disclosures" (arXiv 2605.25865) — six-family
  BOLA taxonomy across family, action type, authorization direction,
  industry sector, identifier format, and exploit mechanism; Action-
  Level Object BOLA and Direct Object Reference BOLA are the two
  dominant families.
- OWASP API Security Top 10 — API1:2023 Broken Object Level
  Authorization (renamed from IDOR in the 2019 edition, ranking
  unchanged as the top API risk).

## Practical Hunting Tips
- Don't stop testing a given object type after confirming its read-path
  is correctly gated — per the empirical data, action/write-path checks
  are more often missing than read-path checks, so a "looks secure"
  read result is not evidence the object type is safe overall.
- Prioritize authenticated business-logic testing on your own test
  account/data over unauthenticated infrastructure scanning (this
  mirrors the general guidance in `bug-bounty/methodology.md`) — BOLA
  specifically requires *two* authenticated identities to test properly
  (one to own an object, one to attempt unauthorized access to it), so
  budget for creating multiple test accounts as a baseline requirement.
- When schema discovery is available (GraphQL, OpenAPI), treat every
  discovered mutation/endpoint as requiring its own explicit BOLA test
  regardless of whether the primary client application ever calls it.

## Real World Examples
- Uber Eats BOLA/IDOR ($2,000 HackerOne bounty).
- Empirical dataset of 84 confirmed BOLA cases across HackerOne
  disclosures 2021-2026, with Action-Level Object BOLA as the largest
  single family at 41.7%.

## References
- https://arxiv.org/abs/2605.25865
- https://nullsecurityx.medium.com/uber-eats-bola-idor-vulnerability-2-000-bounty-technical-write-up-a73c44f9f18f
- https://nrshafi.github.io/broken-access-control-guide/
- https://github.com/OWASP/API-Security/blob/master/editions/2023/en/0xa1-broken-object-level-authorization.md

---
*Added 2026-09-04 via research pass.*
