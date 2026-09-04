# HTTP Request Smuggling

## Summary
Request smuggling exploits disagreement between two HTTP servers in a
chain (front-end proxy/CDN/load balancer + back-end origin) about where
one request ends and the next begins. The attacker crafts a request that
each server parses differently, causing part of the attacker's payload to
be interpreted by the back-end as the start of a *different* request —
either the next legitimate victim's request on a reused connection, or a
second smuggled request the front-end never inspected. Still one of the
highest-leverage bug classes because a single desync can bypass every
front-end security control at once (WAF, auth, rate limiting) and poison
other users' traffic.

## Root Cause
- Two conflicting ways to specify body length in HTTP/1.1:
  `Content-Length` (fixed byte count) and `Transfer-Encoding: chunked`
  (self-delimiting chunks). When a request smuggles *both* headers, or a
  malformed/obfuscated variant of one, front-end and back-end can each
  pick a different one — the classic **CL.TE** / **TE.CL** / **TE.TE**
  desync families.
- HTTP/2 → HTTP/1.1 downgrading at the edge reintroduces the whole
  ambiguity class even for stacks that thought they'd left HTTP/1.1
  parsing behind, because the downgrade step re-serializes the request
  into the ambiguous text format.
- Lenient parsers: many server implementations favor compatibility over
  strict RFC compliance (accepting whitespace before a colon, obs-folded
  header continuation lines, malformed chunk-extension syntax) — every
  such leniency is a potential differential between two otherwise-RFC-
  compliant-looking implementations.

## Attack Flow
1. Fingerprint the front-end/back-end pairing (CDN vendor, reverse proxy,
   origin server/framework) — the specific desync primitive available
   depends entirely on which two parsers are actually stacked.
2. Send a probe request with an ambiguous length specification and a
   timing-based or differential-response oracle (PortSwigger's
   "timeout"/differential technique) to confirm a desync exists before
   attempting anything destructive.
3. Escalate from a confirmed primitive to real impact: smuggle a request
   that lands in front of the *next* real user's request on the same
   backend connection (classic multi-user desync), or smuggle a request
   back to the front-end itself (request "reflection") to poison a cache
   or bypass an auth check enforced only at the edge.

## Exploitation
- **CL.TE / TE.CL classics**: front-end uses `Content-Length`, back-end
  uses `Transfer-Encoding` (or vice versa) — the still-most-common real-
  world pairing, especially where the back-end is an older/embedded HTTP
  stack behind a modern CDN.
- **Malformed chunk-extension smuggling (2026)**: sending a chunk-size
  line with a bare semicolon and no actual extension name after it
  causes some parsers to treat the line as a valid zero-size terminator
  while others keep reading — enough of a parsing split to embed a
  second, backend-only request after what the front-end considers the
  end of the message. Bypasses WAFs/CDNs/load balancers sitting in front
  of a lenient backend.
- **HTTP/2 downgrading desync**: a CRLF sequence injected into an HTTP/2
  header *value* survives HTTP/2's binary framing (which has no line-
  based parsing to catch it) but is re-interpreted as a literal header
  separator once the edge downgrades the request to HTTP/1.1 text for
  the origin — lets an attacker smuggle headers the front-end never saw
  and never had a chance to strip or validate.
- **Obs-folding**: legacy RFC 7230 header-continuation-via-leading-
  whitespace support in one server but not the other produces the same
  class of split as CL.TE, just via header folding instead of body-length
  ambiguity.

## Bypass
- WAFs that pattern-match on well-known smuggling signatures (duplicate
  `Content-Length`, `Transfer-Encoding: chunked, chunked`) are routinely
  bypassed by less-obvious obfuscation of the same underlying ambiguity:
  unusual casing (`TrAnsFer-EncoDing`), tab/whitespace insertion around
  the header name or colon, and the chunk-extension/obs-fold variants
  above that don't match a literal duplicate-header signature at all.
- academic research (WAFFLED, arXiv 2503.10846) demonstrates that parsing
  discrepancies *between the WAF and the origin* — not just between
  front-end and back-end proxies — are themselves an exploitable bypass
  class, i.e. the WAF's own parser can be the desync victim.

## Automation
- Burp Suite's HTTP Request Smuggler extension + manual differential
  timing probes remain the standard tooling; automate the *confirmation*
  step (timeout oracle) at scale across many endpoints of a target before
  investing manual time in exploitation of any single confirmed instance.
- Script systematic fuzzing of chunk-extension syntax variants (trailing
  semicolons, malformed extension names, extra whitespace) against a
  known target stack pairing when hunting for the 2026-style malformed-
  chunk variant specifically.

## Detection
- Server-side: log and alert on requests containing *both*
  `Content-Length` and `Transfer-Encoding` headers, and on any
  non-standard chunk-extension syntax — these should essentially never
  appear in legitimate traffic.
- Differential response/timing signatures during active testing are
  themselves the detection oracle — a request that should time out but
  returns immediately (or vice versa) is the core signal PortSwigger's
  methodology is built around.

## Mitigation
- Prefer HTTP/2 (or HTTP/3) end-to-end where the whole chain supports it
  — binary framing removes the line-based ambiguity that enables the
  entire bug class at the wire-format level.
- Where HTTP/1.1 must remain in the chain, terminate connections after
  every request at the vulnerable hop (disable connection reuse/
  keep-alive) rather than relying purely on parser hardening — this
  bounds the blast radius even if a desync primitive exists.
- Normalize/reject ambiguous requests at the very first hop rather than
  passing them through with a "best guess" interpretation — reject-on-
  ambiguity beats silently picking one interpretation.

## Variant Hunting
- Any new reverse proxy, CDN, or load balancer added to a stack is worth
  a fresh differential-parsing pass against whatever origin server sits
  behind it, even if the origin itself was previously tested against a
  *different* front-end — the vulnerability is a property of the *pair*,
  not either server alone.
- Re-test previously "fixed" targets after any infrastructure migration
  (CDN vendor change, load balancer upgrade, HTTP/2 rollout) — a fix for
  one specific front-end/back-end pairing doesn't carry over to a new
  pairing introduced by an infra change.

## Related CVEs
- CVE-2026-48710 — Kludex Starlette HTTP request/response smuggling,
  added to CISA KEV September 2026 (confirmed actively exploited).

## Related Bug Bounty Reports
- (Populate as specific disclosed smuggling reports are found in future
  research passes — PortSwigger's own research blog and HackerOne
  Hacktivity are the highest-signal sources.)

## Related Research
- PortSwigger Web Security Academy — canonical reference for the full
  technique taxonomy and exploitation labs.
- WAFFLED (arXiv 2503.10846) — "Exploiting Parsing Discrepancies to
  Bypass Web Application Firewalls."
- Outpost24 (2026) — HTTP/2 downgrading exploit walkthrough.

## Practical Hunting Tips
- Always start from the timing/differential-oracle confirmation step
  before crafting an exploitation payload — a huge fraction of wasted
  effort on this bug class comes from skipping straight to exploitation
  attempts against a desync that was never actually confirmed to exist.
- When a target sits behind a well-known CDN, check that CDN vendor's own
  disclosed smuggling history first — CDNs fix specific parser bugs over
  time, and knowing which class was already patched narrows which
  variant is worth trying against the *current* stack.

## Real World Examples
- Malformed chunked-transfer-encoding-extension technique (2026) —
  bare-semicolon chunk extensions causing front-end/back-end parsing
  splits, bypassing WAF/CDN/load-balancer controls.
- CVE-2026-48710 (Starlette) — added to CISA KEV September 2026.

## References
- https://portswigger.net/web-security/request-smuggling
- https://portswigger.net/web-security/request-smuggling/exploiting
- https://cybersecuritynews.com/http-smuggling-attack/
- https://outpost24.com/blog/request-smuggling-http-2-downgrading/
- https://arxiv.org/pdf/2503.10846

---
*Added 2026-09-04 via research pass.*
