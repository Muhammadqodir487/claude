# SAML Single Sign-On Security

## Summary
SAML establishes trust between an Identity Provider (IdP) and a Service
Provider (SP) entirely through an XML digital signature over an
assertion. Nearly every real-world SAML bug is a variant of one root
problem: the code that cryptographically **verifies** a signature and
the code that **extracts** the identity used for authentication operate
on different views of the same XML document. If those views can be made
to disagree — via document restructuring, parser differentials, or
malformed canonicalization — an attacker with no credentials forges a
login as any user, including admins. 2025 supplied strong confirmation:
critical (CVSS 9.3–9.9) signature-wrapping and parser-differential bugs
landed in `ruby-saml` and `samlify`, libraries embedded in large numbers
of downstream SSO integrations, including GitHub Enterprise Server.

## Root Cause
- **Verify/parse mismatch**: the verifier checks that *some* element has
  a valid signature over *some* content, while a separate
  identity-extraction routine (an XPath like `//saml:Assertion`)
  independently re-walks the document to find "the" Assertion to trust.
  If the two can be pointed at different elements, the signature you
  verified is not the identity you use.
- **Dual-parser architectures**: some libraries use one parser to
  extract/verify the signature (e.g. Ruby's REXML) and another to
  canonicalize and hash (e.g. Nokogiri/libxml2). Each has its own
  quirks around namespaces, duplicate attributes, and malformed input —
  a payload can make the two see meaningfully different documents.
- **Canonicalization (C14N) silently degrading**: C14N should produce
  one deterministic byte-serialization of a subtree. When it hits
  something unresolvable (an unresolved relative URI), some
  implementations return an empty string instead of erroring — the
  digest is then computed over nothing, so any payload passes.
- **Signature fails open**: SP code that treats a missing `<Signature>`
  as "nothing to verify" instead of "reject" turns a crypto check into
  an attacker-controlled toggle.
- **Multi-tenant trust confusion**: an SP verifying "signed by *a*
  certificate I trust" rather than "signed by *the* IdP this response
  claims to be from" lets one org's valid signature authenticate into
  another org's tenant.

## Attack Flow
1. Obtain one legitimately signed Response/Assertion — from your own
   low-privilege account, IdP metadata, or an intercepted login (no IdP
   private key needed for wrapping attacks, only for Golden/Silver SAML).
2. Identify which XML parser(s) the SP uses for verification vs.
   attribute/NameID extraction (error messages, library fingerprinting,
   known-CVE version detection).
3. Restructure the document — clone, wrap, relocate, or comment-inject
   around the signed Assertion — so the verifier still validates the
   original element while extraction reads attacker-controlled content.
4. Replay the crafted response to the SP's ACS endpoint and confirm
   authentication as the target identity (e.g. `admin@target.com`).

## Exploitation
- **XSW variants 1–8** (Somorovsky et al., "On Breaking SAML," USENIX
  Security 2012 — the canonical taxonomy): XSW1/2 clone the signed
  Assertion before/after the original so the SP's first/last-match XPath
  reads the unsigned clone; XSW3/4 wrap the signed Assertion *inside* a
  forged parent so the SP reads the outer fake attributes; XSW5/6
  relocate `<Signature>` into the forged element; XSW7/8 hide the
  original inside `Extensions`/`Advice` while the SP reads the forged
  sibling.
- **CVE-2025-47949 (samlify, CVSS 9.9)**: samlify validates the
  signature is cryptographically valid but never confirms the identity
  it hands the app came from *that* signed Assertion. An attacker
  injects a second, unsigned Assertion with a target identity; samlify
  reads the unsigned one. Fixed in 2.10.0.
- **CVE-2025-25291 / -25292 (ruby-saml ≤ 1.17.0)**: found by GitHub
  Security Lab and bounty researcher "ahacker1" — ruby-saml used REXML
  to extract the signature/digest and Nokogiri to canonicalize/verify
  it. An attacker holding one validly signed document can add an extra
  `<Signature>` visible only to Nokogiri while REXML extracts a
  fabricated Assertion whose digest checks out. Fixed in 1.18.0 (Mar
  2025); hit GitHub Enterprise Server's own SSO, disclosed via
  HackerOne #2579939.
- **CVE-2025-66567 / -66568 ("void canonicalization")**: PortSwigger
  Research ("The Fragile Lock," Dec 2025) — an incomplete fix for
  CVE-2025-25292 plus a new class: libxml2's C14N silently returns an
  empty string on an unresolvable node, and ruby-saml digests that empty
  string regardless of actual content. Same research documents
  **attribute pollution** (duplicate/namespaced `ID` read inconsistently
  across parsers) and **namespace confusion** (REXML treating reserved
  namespace declarations as regular attributes to hide a `<Signature>`)
  — also affecting PHP-SAML and `xmlseclibs`.
- **Golden SAML** (SolarWinds-era research, CyberArk origin):
  compromising an on-prem AD FS signing key lets an attacker mint
  arbitrary assertions for any user, including Global Admin, entirely
  offline — bypassing MFA and passwords.
- **Silver SAML** (Semperis, 2025): the cloud sibling — orgs that
  migrated to Entra ID but imported an externally-generated signing
  certificate (instead of Entra's managed cert) reintroduce the same
  risk, since whoever holds that key can forge Entra-trusted responses.

## Bypass
- **Signature exclusion**: delete `<Signature>` entirely — works when
  the SP treats "no signature" as "nothing to verify."
- **Comment injection**: `admin@test.com<!---->@evil.com` in a NameID —
  some parsers strip comments on a later pass, so the authorization
  value differs from what was actually signed.
- **Duplicate/ambiguous IDs**: two elements sharing the `ID` the
  signature's `URI` references — parsers disagree on which resolves.
- **Replay**: reuse a captured Response when `NotOnOrAfter` isn't
  enforced tightly or consumed Assertion IDs aren't tracked — no
  signature bypass needed if the assertion is simply reusable.
- **IdP confusion**: a response signed by a legitimate *customer* IdP
  cert but targeted at a *different* tenant's SP, when trust is global
  rather than per-tenant.
- **Algorithm downgrade**: force/accept SHA-1 where the SP hasn't
  pinned an allowed algorithm list.

## Automation
- **SAML Raider** (Burp extension, `PortSwigger/saml-raider`) — edits
  SAMLRequest/Response params, re-signs or strips signatures, manages
  attacker certs, and generates all eight XSW variants against a
  captured response.
- Custom `lxml`/Nokogiri scripts for canonicalization edge cases (void
  C14N, attribute pollution) that off-the-shelf tooling hasn't
  templated yet — worth building whenever a new parser-differential
  class is published, since tooling lags research by months.
- Library/version fingerprinting (error messages, JS bundles) to
  shortlist known CVEs (samlify < 2.10.0, ruby-saml < 1.18.0) before
  hand-crafting a novel payload.

## Detection
- Alert on any Response with more than one `<Assertion>` or
  `<Signature>` — legitimate IdPs issue exactly one of each.
- Diff the element the verifier validated against the element the
  application actually read attributes from; any mismatch is a
  wrapping attempt regardless of payload success.
- Flag XML comments inside identity-bearing text nodes.
- Track consumed Assertion IDs and alert on reuse or unusually long
  `NotOnOrAfter` windows.

## Mitigation
- **Canonicalize once, verify over the canonicalized copy, then extract
  identity from that same copy** — never re-parse the raw document
  separately for extraction. This single fix closes nearly every XSW
  and parser-differential variant.
- Enforce exactly one `<Signature>`/`<Assertion>` per Response; reject
  outright rather than picking first/last when more than one exists.
- Use one well-audited XML library end-to-end — mixing parsers across
  the verify/extract boundary is the direct root cause of
  CVE-2025-25291/25292/66567/66568.
- Treat any C14N failure as a hard verification failure.
- Short assertion validity windows plus a single-use replay cache
  (often available but off by default).
- Scope IdP trust per tenant in multi-tenant SaaS.
- Pin allowed signature algorithms; reject SHA-1.
- Patch immediately on advisory; don't hand-roll XML signature
  verification.
- For cloud IdPs: prefer the platform's managed signing cert over an
  externally-generated one; if external certs are required, protect the
  key like a domain-admin credential (HSM/Key Vault, least privilege,
  rotation) — the exact gap Silver SAML exploits.

## Variant Hunting
- Re-test any SP on `ruby-saml`, `samlify`, `python3-saml`,
  `simpleSAMLphp`, or `xmlseclibs` after every advisory — CVE-2025-66567
  was an incomplete fix for CVE-2025-25292, showing this class gets
  partially patched and reopened repeatedly.
- Check whether SLO requests, metadata processing, or artifact binding
  reuse the same verification path — secondary flows get less scrutiny.
- In multi-tenant products, test cross-tenant IdP metadata swap even
  when primary signature verification looks solid.
- Re-check "fixed" libraries for the *other* half of a dual-parser
  architecture — a fix to the extraction parser can leave the
  verification parser's canonicalization untouched.

## Related CVEs
- CVE-2025-47949 — samlify, signature wrapping via unsigned injected
  Assertion, CVSS 9.9, fixed in 2.10.0.
- CVE-2025-25291 / CVE-2025-25292 — ruby-saml, REXML/Nokogiri parser
  differential enabling assertion forgery, fixed in 1.18.0.
- CVE-2025-66567 / CVE-2025-66568 — ruby-saml, incomplete fix for
  CVE-2025-25292 plus a new "void canonicalization" C14N bypass,
  disclosed by PortSwigger Research, CVSS ~9.3.

## Related Bug Bounty Reports
- HackerOne #2579939 (GitHub Enterprise Server) — "SAML Signature
  verification bypass allows logging into any user," ahacker1's
  ruby-saml parser-differential finding, basis for CVE-2025-25291/25292.
- HackerOne #812064 (Rocket.Chat) — SAML authentication bypass, an
  example of SP-side validation logic bugs outside the library layer.

## Related Research
- Somorovsky, Mainka, Schwenk et al., "On Breaking SAML: Be Whoever You
  Want to Be" (USENIX Security 2012) — the original XSW1-8 taxonomy.
- PortSwigger Research, "The Fragile Lock" (Dec 2025) — void
  canonicalization, attribute pollution, and namespace confusion as
  new attack classes beyond classic XSW.
- GitHub Blog, "Sign in as anyone: Bypassing SAML SSO authentication
  with parser differentials" — vendor's own writeup of CVE-2025-25291/92.
- Semperis, "Meet Silver SAML: Golden SAML in the Cloud."
- **Cross-reference**: see `web-security/jwt-oauth.md` — JWT
  algorithm-confusion/`kid`-injection and SAML's XSW/parser-differential
  bugs are structurally the same category: a signature is verified over
  one representation of the data while a separate path extracts trust
  from a different representation of the same object. Any
  assertion-based federated-identity format should be hunted with the
  same question: "what exactly did the verifier hash, versus what did
  the application actually read?"

## Practical Hunting Tips
- Capture a raw legitimate Response first and manipulate a copy — SAML
  Raider needs a valid baseline to wrap around.
- Fingerprint the library/version before guessing payloads; try a
  documented CVE PoC before hand-building a novel variant.
- Test signature exclusion and basic XSW1/2 first — cheapest tests,
  still work against a surprising number of unpatched SPs.
- Test SLO (logout) and artifact/backend-channel exchanges separately —
  frequently validated by different, less-hardened code.
- In multi-tenant products, always test cross-tenant IdP metadata
  swap — a distinct bug class commonly missed by crypto-focused testers.

## Real World Examples
- GitHub Enterprise Server (CVE-2025-25291/25292): a network-adjacent
  attacker forging a SAML response could gain site-administrator
  access — from GitHub's own ruby-saml dependency, notable since GitHub
  is both vendor and the bounty program that surfaced it.
- samlify (CVE-2025-47949, CVSS 9.9): widely embedded in Node.js SSO
  integrations; a textbook wrapping bug reached critical severity from
  pure logic gap, no exotic parser trickery required.
- SolarWinds-era Golden SAML abuse: real-world confirmation that a
  compromised IdP signing key defeats SSO trust entirely — the incident
  that drove migration to cloud IdPs, which in turn created the Silver
  SAML exposure documented by Semperis in 2025.

## References
- https://portswigger.net/research/the-fragile-lock
- https://github.blog/security/sign-in-as-anyone-bypassing-saml-sso-authentication-with-parser-differentials/
- https://hackerone.com/reports/2579939
- https://www.endorlabs.com/learn/cve-2025-47949-reveals-flaw-in-samlify-that-opens-door-to-saml-single-sign-on-bypass
- https://github.com/advisories/GHSA-r683-v43c-6xqv
- https://rubysec.com/advisories/CVE-2025-66568/
- https://www.semperis.com/blog/meet-silver-saml/
- https://github.com/PortSwigger/saml-raider
- https://www.usenix.org/system/files/conference/usenixsecurity12/sec12-final91.pdf
- https://portswigger.net/web-security/saml

---
*Added 2026-09-04 via research pass.*
