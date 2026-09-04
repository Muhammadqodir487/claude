# Bug Bounty Methodology — Recon → Triage → Chaining → Reporting

## Summary
High-signal bug bounty work is less about payload libraries and more
about (1) mapping attack surface more completely than the target's own
team expects, (2) recognizing which discovered weaknesses are worth
chaining together for real impact, and (3) writing reports that make
triage trivially fast. This file captures the workflow, not any single
vulnerability class (see `web-security/` for those).

## Recon Workflow
1. **Scope parsing** — read the program brief literally before touching
   anything. Distinguish: exact assets listed as full URLs (test only
   that URL) vs. "Domain" type scope (often implies the whole zone incl.
   subdomains) vs. explicit wildcard (`*.example.com`). When ambiguous,
   the safer default is to treat it as the exact asset unless the
   program's own language or asset "type" field says otherwise.
2. **Passive subdomain enumeration** — certificate transparency logs
   (crt.sh), passive DNS aggregators (subfinder pulls from many of
   these at once). Passive-only recon touches third-party data sources,
   not the target's own infrastructure, so it's safe even under strict
   "no automated scanners" program rules — the *target* never receives a
   probe from this step.
3. **Liveness + tech fingerprinting** — HTTP probing (status, title,
   redirect chain, tech stack via response headers/JS signatures).
   Compare tech stacks across subdomains to spot the outlier (the one
   still on an old framework/CMS while the rest were migrated).
4. **DNS-record cross-referencing** — resolve every discovered hostname's
   CNAME/A record, not just check if it's "alive" over HTTP. This
   surfaces two very different high-value patterns:
   - **Private IP disclosure**: public DNS resolving to RFC1918 space
     reveals internal network topology (VPC CIDR ranges, internal tool
     names) even when the host itself is unreachable — legitimate
     low/informational finding, and free reconnaissance-value for any
     future internal-network-adjacent finding.
   - **Dangling third-party CNAMEs**: CNAME to a SaaS platform
     (`*.cloudfront.net`, `*.azurefd.net`, `*.wpengine.com`,
     `*.herokuapp.com`, `*.github.io`, GCS-backed custom domains) with no
     active resource behind it → subdomain takeover candidate. The
     platform's own "unclaimed"/"not found" error page is usually
     distinctive enough to identify with a single unauthenticated GET —
     no exploitation needed to *identify* the candidate, only to fully
     prove it.
5. **Content discovery** — only after understanding what's actually live;
   avoid blind brute-forcing of massive wordlists against production
   under strict "no automated scanner" programs — a small, curated,
   manually-reasoned path list beats an indiscriminate 50k-word gobuster
   run both technically (less noise, less risk of appearing as an
   attack) and program-compliance-wise.

## Triage: What's Actually Worth Pursuing
- Cross off anything in the program's explicit out-of-scope list *first*
  — it's the highest-signal document in the whole brief, because it
  tells you exactly which classes of finding the program has already
  seen too many of (and, often, which ones they've quietly accepted as
  residual risk).
- Prefer authenticated business-logic testing on your *own* test
  account/data over unauthenticated infrastructure poking, when the
  program allows account creation — access control and business logic
  bugs are systematically underreported relative to their real
  prevalence because they require actually using the product, not just
  scanning it.
- A single "banner disclosure" or "internal hostname leak" is rarely
  worth a report on its own merit under most modern program rules — but
  is worth *keeping notes on*, because two or three independently-weak
  signals often combine into a real chain (see below).

## Chaining Patterns (real leverage)
- Internal hostname/IP disclosure (recon) + a later-discovered SSRF
  elsewhere in the same target → the disclosed internal hostname becomes
  a *known-good target* for the SSRF instead of a blind guess.
- Subdomain takeover + `.domain.com`-scoped session cookies → cookie
  theft/session fixation from the takeover subdomain against the main
  application, turning an "informational" takeover into an account
  takeover primitive.
- Open redirect (usually low on its own) + OAuth `redirect_uri`
  substring-matching → authorization code/token theft (this is exactly
  why "open redirect" is almost always scoped as "unless additional
  security impact can be demonstrated" — the OAuth chain *is* that
  additional impact).
- Stored input (comment, profile field, filename) that's safely escaped
  in the primary web client but consumed *unescaped* by a secondary
  surface (email digest HTML, admin dashboard, mobile app webview,
  desktop Electron app with a different/absent CSP, PDF export) — always
  test where else stored data resurfaces, not just where it was entered.
- Multiple weak/dangling entries under the *same* root cause (e.g., one
  CDN-collector-vendor CNAME pattern repeated across many brand
  subdomains) should be combined into a single report per most programs'
  duplicate-handling rules — but the write-up is *stronger*, not weaker,
  for showing the pattern is systemic (indicates a process gap, not a
  one-off).

## Reporting Strategy (what makes triage fast)
- Lead with a one-paragraph summary a non-specialist triager can grok in
  10 seconds: what's broken, how bad, how to see it.
- Give the *exact* request (method, URL, headers, body) — not a
  paraphrase — plus the exact response that proves the claim. Screenshots
  supplement, never replace, raw request/response text.
- State plainly what you did *not* do and why (e.g., "did not complete
  the takeover to avoid creating real infrastructure without your
  sign-off — the platform's own 'unclaimed domain' response should be
  sufficient for your team to verify directly"). This reads as
  professionalism, not as an incomplete report, and avoids
  program-rule violations around causing real-world impact.
- Explicitly separate "confirmed" from "anomalous/needs investigation"
  findings when your evidence is genuinely inconclusive (e.g., an
  endpoint that behaves differently on a malformed payload, then
  stops responding — plausible SQLi *or* plausible WAF/rate-limit
  reaction; say so honestly rather than overclaiming). Programs
  consistently respond better to calibrated honesty than to inflated
  severity claims that don't survive their own verification.

## False-Positive Reduction
- SPA/catch-all routing: a "200 OK on every path including `/.git/config`"
  result is a classic false positive — confirm by diffing response
  bodies (hash) across a known-good path, a known-bad/nonsense path, and
  the "interesting" path; identical hashes = client-side fallback
  routing, not real exposure.
- API responses that echo back exactly what was submitted (mass
  assignment tests) prove nothing by themselves — check the field is
  actually *persisted* and *affects behavior* on a subsequent read, not
  just accepted in the create/update response.

## Automation Ideas
- Maintain a small, hand-curated (not 10k-line) path/parameter wordlist
  per target *category* (SaaS admin panels, e-commerce checkout flows,
  SSO providers) built from what you've personally confirmed matters —
  higher signal than generic wordlists, and less likely to look like
  indiscriminate scanning under strict program rules.
- Tag every request with the program's required identifier
  (custom header or User-Agent suffix) from the very first recon request,
  not just once testing "starts" — programs use this to distinguish
  researcher traffic from real attacks in their logs, and a gap in
  tagging can itself trigger unwanted incident response.

## Practical Hunting Tips
- Read the *out-of-scope* list before the *in-scope* list — it teaches
  you more, faster, about what the target's threat model already covers.
- When a program bans automated scanners explicitly and repeatedly
  ("we have these tools too, don't even think about using them"),
  respect it literally — treat even "just checking" a scanner run as a
  program-compliance risk, not just an ethical nicety; being removed
  from a program forecloses all future bounty potential there.
- When PII or real customer data might plausibly appear (financial,
  healthcare, tax platforms), decide *in advance* what you will do if you
  see it (stop, don't store, don't screenshot it, notify immediately) —
  don't improvise that decision in the moment.

## Related Research
- Every major platform's public disclosure/duplicate-handling policy
  (HackerOne, Bugcrowd) — read these as methodology documents, not just
  legal text; they encode what triagers actually reward.
- @NahamSec, @STÖK, @Jhaddix public methodology talks/streams — strong
  source for current-generation recon tooling opinions (verify currency;
  tool landscape shifts fast).

## Real World Examples
- This KB's own session log (2026-09-03) contains three live case
  studies worth re-reading as methodology examples:
  1. Essity/HackerOne engagement — systemic dangling-CNAME pattern
     (`c.<code>.brand.com`) found across 8+ unrelated brand domains,
     correctly identified as one underlying root cause per the
     duplicate-handling rule, with an honest caveat about
     ACM-cert-validation limiting real exploitability.
  2. Same engagement — a genuine Azure App Service takeover candidate
     was found already claimed by another researcher (visible via their
     left-behind proof-of-concept page with name + date) — a clean
     real-world illustration of "first-to-report wins" and why moving
     fast on subdomain-takeover classes matters.
  3. Taxwell/HackerOne engagement — a WP Engine dangling-domain takeover
     was identified and reported using only the platform's own
     "unclaimed domain" error response as evidence, explicitly declining
     to spend money/create real infrastructure to complete the PoC,
     since the target asset was bounty-ineligible anyway — a template
     for cost/benefit-aware reporting.

## References
- HackerOne Hacktivity (public disclosed reports) — best free source of
  real accepted-report structure and severity calibration.
- Bugcrowd VRT (Vulnerability Rating Taxonomy) — useful even off-platform
  as a severity-calibration reference.
