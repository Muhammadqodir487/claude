# Web Cache Poisoning & Web Cache Deception

## Summary
Two related but distinct bug classes that both abuse the gap between
"what the cache thinks it's storing/serving" and "what the origin server
actually did": **cache poisoning** tricks a shared cache into storing an
*attacker-influenced response* and serving it to other users (turning an
unkeyed input into a stored, repeatable attack against everyone who hits
the cached URL); **cache deception** tricks the cache into storing a
*victim's own sensitive, personalized response* under a URL the attacker
can then request themselves. Both ultimately trace back to a **cache
key vs. origin-processing mismatch** — the cache and the origin disagree
about what makes two requests "the same," and that disagreement is the
entire exploit primitive.

## Root Cause
- **Unkeyed inputs influencing the response**: headers, query
  parameters, or other request components that affect the origin's
  response but are *not* part of the cache key — the cache will serve
  the same cached response to every subsequent visitor regardless of
  their own request, even though the response content was determined by
  one attacker's unkeyed input.
- **URL parsing discrepancies between CDN and origin** (the 2026-era
  frontier of this bug class): different frameworks treat different
  characters as path delimiters (Spring: semicolons, Rails: dots,
  OpenLiteSpeed: null bytes, Nginx: newlines) and different platforms
  normalize URL encoding / dot-segment resolution differently before
  deciding what to cache. When the cache's notion of "this looks like a
  static file" and the origin's notion of "this routes to a dynamic
  handler" disagree, an attacker can craft one URL that the cache stores
  under a static-looking key while the origin actually serves dynamic,
  personalized, or attacker-influenced content.
- **Cache deception specifically**: caches frequently apply blanket
  "cache anything that looks like a static asset" rules based on
  extension/path pattern matching, without confirming the origin
  actually treated the request the same way — appending a fake static
  extension to a dynamic, authenticated endpoint can trick the cache
  into storing that user's personalized response as if it were a shared
  static asset.

## Attack Flow
1. **Cache poisoning**: identify an unkeyed input (test with `param
   miner`-style automated header/param discovery) that measurably
   changes the response, then confirm the changed response actually
   gets cached and served to a fresh, unauthenticated request (not just
   reflected back to the same client).
2. **Cache deception**: find an authenticated endpoint returning
   sensitive/personalized data, then craft a URL variant (path
   confusion, fake extension, delimiter trick) that the cache's rule set
   will treat as cacheable static content while the origin still serves
   the personalized response under session context — visit as the
   victim (or get the victim to visit), then request the same crafted
   URL unauthenticated to retrieve their cached response.
3. For both: escalate from "the cache serves *a* different response" to
   real impact — cache poisoning most often escalates to stored XSS
   (poisoning with an XSS payload) or open-redirect-to-malicious-script
   loading; deception escalates directly to sensitive data
   exposure/account takeover if the cached response contains session
   tokens or PII.

## Exploitation
- **Delimiter-based cache-key confusion**: appending a backend-specific
  delimiter plus a static-looking suffix (e.g., `/myAccount;var=1.js`)
  causes some cache layers to treat the request as a cacheable `.js`
  static asset while the origin still routes it to the dynamic
  `/myAccount` handler — caching a personalized/dynamic response under a
  static-asset cache key.
- **Normalization-discrepancy poisoning**: exploiting the fact that
  "Microsoft Azure, Amazon CloudFront, and Imperva normalize the path
  before evaluating cache rules by default," while "Cloudflare, Google
  Cloud, and Fastly don't normalize the path before evaluating cache
  rules" — a URL crafted to be interpreted one way by a
  non-normalizing edge cache and a different way by the (possibly
  different) origin/CDN layer behind it lets an attacker choose exactly
  which layer's interpretation ends up cached.
- **"Un-exploitable" primitive escalation via cache-key confusion**: an
  `X-Forwarded-Host`-driven open redirect that's normally unusable
  (browsers won't let an attacker set arbitrary request headers)
  becomes a real stored attack once combined with cache-key confusion —
  poison the path in the cache so it redirects to an attacker-controlled
  script, turning a previously low-severity, hard-to-trigger primitive
  into a stored, browser-triggerable one.
- **Cloudflare "Deception Armor" bypass via `.avif` extension**: a
  documented bypass of Cloudflare's own cache-deception protection
  feature by using the `.avif` file extension specifically, making
  cache deception possible again against origin servers that were
  otherwise protected — a reminder that vendor-provided
  anti-cache-deception features need their own extension/pattern
  coverage re-verified, not assumed complete.

## Bypass
- Anti-cache-deception features that pattern-match a fixed list of
  "known static extensions" are bypassed by any extension outside that
  list that the *origin* still treats permissively enough to route to a
  dynamic handler — the Cloudflare `.avif` case is the concrete 2026
  example, and the general lesson (test extensions outside whatever list
  a specific protection covers) generalizes to any similar feature.
- WAF/cache rules based on raw-character blocklisting for path
  delimiters miss the fact that the *specific* delimiter character that
  matters is backend-framework-dependent — a rule tuned against one
  framework's delimiter set doesn't generalize to a different backend
  framework's own delimiter conventions.

## Automation
- **Param Miner** (Burp extension) — automated discovery of unkeyed
  inputs that influence responses, the standard first step in any cache
  poisoning assessment.
- Systematic extension/delimiter fuzzing against a target's specific
  CDN+origin combination (informed by which vendor normalizes vs.
  doesn't, per the research above) to find the specific parsing
  discrepancy that combination exposes.

## Detection
- Cache-hit-ratio and cache-key monitoring: alert on cache entries whose
  stored key doesn't match the expected canonical form for that path
  pattern (e.g., a `.js`-suffixed cache entry whose content-type/response
  body doesn't actually look like a static JS file).
- Response-content diffing: periodically re-request cached URLs
  unauthenticated and diff against expected static content — a
  personalized/dynamic response appearing under a supposedly-static
  cached URL is a direct signal of active cache deception.

## Mitigation
- Include every input that measurably affects the response in the cache
  key, or explicitly strip/normalize it server-side before it can reach
  response-generation logic — don't let "convenient default" unkeyed
  headers (like `X-Forwarded-Host`) silently influence cached content.
- Normalize the URL identically at every layer in the CDN→origin chain
  *before* cache-rule evaluation — per the research, choosing to
  normalize-before-caching (as Azure/CloudFront/Imperva do) closes the
  specific discrepancy class that non-normalizing platforms
  (Cloudflare/Google Cloud/Fastly, by default configuration) remain
  exposed to.
- Never apply blanket "cache if it looks like a static extension" rules
  to authenticated/dynamic routes — explicitly exclude any path that can
  return personalized/session-dependent content from extension-based
  caching heuristics, regardless of what suffix is appended to the URL.

## Variant Hunting
- Any CDN/cache-vendor's own anti-cache-deception feature is worth
  testing against extensions/patterns *outside* whatever list it's
  documented to cover — the Cloudflare `.avif` bypass shows this
  generalizes as a technique class, not a one-off Cloudflare bug.
- Test every backend framework's own specific path-delimiter convention
  against every CDN/cache layer in front of it — since the exploitable
  discrepancy is defined by the *specific pairing*, a finding against
  one framework+CDN combination doesn't rule out (or confirm) the same
  finding against a different pairing at the same organization.
- Re-test any endpoint previously flagged "unexploitable due to browser
  header restrictions" (classic open redirect via a header browsers
  won't let attackers set) for cache-key-confusion-based escalation —
  this is a systematic pattern for upgrading previously-dismissed
  low-severity findings.

## Related CVEs
- (Cache poisoning/deception findings are typically disclosed as
  bug-bounty reports or CDN-vendor advisories rather than assigned
  CVEs — populate specific CDN-vendor security advisories here as
  found.)

## Related Bug Bounty Reports
- Cloudflare Public Bug Bounty (HackerOne #1391635) — bypassing
  Cloudflare's cache-deception protection.
- A curated set of 20+ real bug bounty cache-poisoning reports has
  reportedly earned researchers over $100,000 in combined bounties,
  per community case-study analysis — confirms this remains one of the
  highest-value bug classes to specialize in as of 2026.

## Related Research
- PortSwigger Research — "Gotta cache 'em all: bending the rules of web
  cache exploitation" (URL parsing discrepancies across CDN/origin
  combinations, delimiter and normalization-based techniques).
- Intigriti — "Exploiting Web Cache Poisoning: Advanced Exploitation
  Guide."

## Practical Hunting Tips
- Always check both directions of the CDN/origin normalization
  relationship for a given target — test whether the *edge* or the
  *origin* is the one deviating from strict RFC path/URL normalization,
  since the exploitable direction depends on which layer you can
  actually observe caching behavior at.
- When a target uses a well-known CDN, check that CDN's specific
  documented normalization behavior (per the Azure/CloudFront/Imperva
  vs. Cloudflare/Google Cloud/Fastly split above) before spending time
  fuzzing blind — this narrows which technique family is worth trying
  first.

## Real World Examples
- Cloudflare Deception Armor `.avif`-extension bypass (HackerOne
  #1391635).
- X-Forwarded-Host open-redirect escalated to stored malicious-script
  loading via cache-key confusion (PortSwigger "Gotta cache 'em all"
  research).

## References
- https://portswigger.net/research/gotta-cache-em-all
- https://hackerone.com/reports/1391635
- https://www.intigriti.com/researchers/blog/hacking-tools/exploiting-web-cache-poisoning-vulnerabilities
- https://medium.com/@Aacle/20-cache-poisoning-case-study-depth-analysis-of-real-world-bug-reports-d6aa02a6a44f

---
*Added 2026-09-04 via research pass.*
