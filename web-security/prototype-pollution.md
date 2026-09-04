# Prototype Pollution

## Summary
JavaScript-specific vulnerability class where an attacker injects
properties onto `Object.prototype` (or another built-in prototype) via
an object-merge/clone/assignment operation that doesn't guard against
`__proto__`, `constructor.prototype`, or (increasingly, post-mitigation)
`Array.prototype`-mediated paths. Because *every* plain object in the
runtime inherits from the polluted prototype, the impact is entirely
determined by what the rest of the application happens to do with
attacker-controlled property values it never explicitly set — ranging
from client-side DOM XSS to full server-side RCE.

## Root Cause
- Recursive merge/extend/clone utility functions (`_.merge`, `$.extend`,
  hand-rolled `deepMerge`) that copy keys from an untrusted object onto a
  target without excluding dangerous key names (`__proto__`,
  `constructor`, `prototype`).
- **Incomplete denylist mitigations are the single most common root
  cause of *bypassed* fixes**: a check that blocks the literal string
  `__proto__` but not equivalent access paths (`constructor.prototype`),
  or one that checks `indexOf`/substring containment on user input
  without accounting for `Array.prototype`-based traversal, as seen in
  CVE-2026-27212 (Swiper) — the original 2025-era fix checked for a
  forbidden key but could still be defeated by supplying a crafted input
  using `Array.prototype` instead of `Object.prototype` directly.
- Client-side pollution reaching a `document.write`/`innerHTML`/template-
  engine sink turns into DOM XSS; server-side pollution reaching a
  `child_process.spawn`/`fork` call (which internally reads polluted
  `.env`/config-like properties) or a template engine's option object
  turns into RCE.

## Attack Flow
1. Identify a merge/clone/config-parsing sink that accepts attacker-
   influenced JSON or query-string input (deep merge of request body
   into a config object is the most common real-world entry point).
2. Confirm pollution with an inert, easily-observable property (e.g.
   pollute a property, then check via a separate request/response whether
   a freshly-created unrelated object exhibits that property) before
   attempting anything with real impact.
3. Identify a **gadget**: existing application/library code that reads a
   property from a plain object *without it ever being explicitly set on
   that object* — meaning it's silently falling back to the (now
   polluted) prototype. Common gadget classes: template-engine option
   objects, ORM/query-builder option objects, `child_process` argument/
   environment handling.
4. Chain pollution → gadget to reach the actual impact (XSS, auth
   bypass, DoS via `Object.prototype` property that breaks control flow
   application-wide, or RCE).

## Exploitation
- **Client-side → XSS**: pollute a property later read by a client-side
  templating/DOM-manipulation library as if it were legitimate
  configuration, injecting attacker HTML/script into a sink the
  application never intended to be attacker-controlled.
- **Server-side → RCE via `child_process`**: when a process is spawned
  via `fork`/`spawn`, Node's internal `normalizeSpawnArguments` reads
  from an options object — polluting `.env` on `Object.prototype` lets
  an attacker inject new environment variables into every subsequently
  spawned child process without the calling code ever passing them
  explicitly. One documented technique stores a malicious Node.js
  payload inside `argv0` via `/proc/self/cmdline` and gets it `require`d
  in place of `/proc/self/environ`, achieving code execution purely
  through environment-variable-mediated pollution.
- **CVE-2026-27212 (Swiper, CVSS 9.4)**: prototype pollution in the
  `extend()` utility (`shared/utils.mjs`) affecting swiper >=6.5.1,
  <12.1.2 — tens of thousands of production frontends depend on this
  slider library. A prior fix checked user input for a forbidden key via
  `indexOf`, but crafted input using `Array.prototype` instead of a
  direct object path still reaches `Object.prototype`, defeating the
  mitigation. Confirmed exploitable on both Windows and Linux, Node and
  Bun runtimes. Impact: auth bypass, DoS, and RCE in any downstream
  application processing attacker-controlled input through Swiper.
  Fixed in 12.1.2.

## Bypass
- **Denylist-check bypasses**: any mitigation that filters `__proto__`
  as a literal string is a first-pass fix, not a real fix — test
  `constructor.prototype`, case variation, and (per CVE-2026-27212)
  `Array.prototype`-relative access paths that reach the same
  destination through a different property-traversal route the check
  didn't anticipate.
- **Bracket vs. dot notation / JSON key encoding**: differences in how a
  validator parses a key (`a[__proto__][b]` in query-string form vs. a
  nested JSON object) can smuggle the dangerous key past a check written
  for only one input shape.

## Automation
- Static analysis: grep dependency trees for known-vulnerable versions
  of common merge utilities (lodash `merge`/`defaultsDeep` before their
  respective fixed versions, hand-rolled recursive-merge functions with
  no key filtering at all) as a fast triage pass before manual dynamic
  testing.
- Dynamic detection: automated tools (e.g. server-side prototype
  pollution scanners referenced in YesWeHack's methodology) send a
  battery of known payload shapes against every JSON-accepting endpoint
  and diff subsequent responses for evidence of cross-request state
  bleed.

## Detection
- Runtime: `Object.freeze(Object.prototype)` in a canary/monitoring
  build immediately throws on any pollution attempt, making it a cheap
  detection tripwire in a staging environment even where it's too
  disruptive to ship to production unmodified.
- Log and alert on request bodies containing `__proto__`,
  `constructor.prototype`, or unexpected deep-nesting depth into known
  merge-consuming endpoints — legitimate traffic essentially never needs
  these key shapes.

## Mitigation
- Use `Object.create(null)` or `Map` for any object that will hold
  attacker-influenced keys, removing the prototype chain entirely rather
  than trying to filter every dangerous path onto it.
- Validate merge/clone utility versions against current CVE advisories
  specifically — this bug class recurs constantly in "boring" utility
  libraries (slider/carousel libraries, form builders, config parsers)
  that aren't anyone's primary security-review target.
- Prefer `structuredClone` or explicit allowlisted-key copying over
  generic recursive merge for anything touching untrusted input.

## Variant Hunting
- Every library shipping its own hand-rolled `extend`/`merge`/`deepCopy`
  utility (rather than a well-audited shared one) is a candidate for the
  same bug class — check UI component libraries, form/validation
  libraries, and config-loading utilities first, since they're the most
  common place a project reinvents this wheel.
- Re-test any library that previously patched a prototype-pollution CVE
  with a denylist-style fix (rather than switching to `Object.create(null)`
  or a Map) for the same class of bypass CVE-2026-27212 demonstrated —
  denylist fixes for this bug class have a poor track record of being
  complete on the first attempt.

## Related CVEs
- CVE-2026-27212 — Swiper, CVSS 9.4, prototype pollution → auth bypass/
  DoS/RCE, denylist-bypass root cause.

## Related Bug Bounty Reports
- (Populate as specific disclosed reports are found — HackTricks and
  s1r1us's research blog document technique-level writeups rather than
  single disclosed reports; add platform-specific reports here as found.)

## Related Research
- HackTricks — "Prototype Pollution to RCE" (Node.js-specific gadget
  catalogue, including the `child_process`/`argv0`/`/proc/self/cmdline`
  technique).
- s1r1us — Prototype Pollution research (blog.s1r1us.ninja/research/PP).
- YesWeHack Learning Bug Bounty — server-side prototype pollution
  detection/exploitation guide.

## Practical Hunting Tips
- Don't stop testing after confirming a *denylist* mitigation blocks the
  obvious `__proto__` payload — the CVE-2026-27212 pattern (bypass via
  `Array.prototype`) shows the fix itself is worth attacking as its own
  target once the base vulnerability is denylist-patched.
- Prioritize UI/frontend component libraries (sliders, carousels, date
  pickers, rich text editors) for this class specifically — they're
  widely depended on, rarely security-audited, and frequently implement
  their own merge/extend utility rather than importing a hardened one.

## Real World Examples
- CVE-2026-27212 (Swiper) — CVSS 9.4, denylist-bypass prototype
  pollution affecting a slider library used across tens of thousands of
  production frontends.

## References
- https://github.com/advisories/GHSA-hmx5-qpq5-p643
- https://securityonline.info/cve-2026-27212-critical-swiper-prototype-pollution-flaw-cvss-9-4-exposes-global-apps/
- https://book.hacktricks.xyz/pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce
- https://www.yeswehack.com/learn-bug-bounty/server-side-prototype-pollution-how-to-detect-and-exploit

---
*Added 2026-09-04 via research pass.*
