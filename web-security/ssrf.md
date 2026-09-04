# Server-Side Request Forgery (SSRF)

## Summary
SSRF occurs when an attacker can induce a server to make an HTTP(S) or
other protocol request to a destination the attacker controls or chooses,
where the server's network position grants access the attacker wouldn't
otherwise have (internal services, cloud metadata, loopback, other tenants'
resources). Modern SSRF findings are almost always about **filter bypass**
against an existing (often naive) allowlist/denylist, not "raw" unfiltered
SSRF — those are rare in mature targets now.

## Root Cause
Any feature where the server fetches a user-influenced URL server-side:
webhooks, "import from URL," PDF/screenshot generators, link previews/
unfurling, image proxies, SSO metadata URL fields, XML external entity
resolution, PDF generation libraries (wkhtmltopdf, Puppeteer via SSR),
GraphQL federation gateways, and internal microservice-to-microservice
calls where a downstream service trusts an upstream-supplied URL.

## Attack Flow
1. Identify a feature that takes a URL, or an object that resolves to one
   (import, avatar-from-URL, "connect your calendar" OAuth discovery URL,
   XML/SOAP with external entities, PDF export, favicon fetchers).
2. Confirm out-of-band interaction (OAST — Burp Collaborator / interactsh
   / your own DNS+HTTP logger) to prove the server itself makes the
   request (not the client).
3. Redirect the target toward internal ranges / cloud metadata / other
   internal ports.
4. Escalate: read internal admin panels, pivot to RCE via internal
   services with weak auth, or steal cloud credentials from metadata
   services.

## Exploitation
- **Cloud metadata theft** (classic, still common):
  - AWS IMDSv1: `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>`
  - AWS IMDSv2 requires a `PUT` token first (`X-aws-ec2-metadata-token-ttl-seconds`)
    — SSRF via a GET-only primitive often can't reach IMDSv2 unless the
    app lets you set arbitrary methods/headers (e.g., via a webhook that
    lets you specify method+headers, or a PDF renderer executing
    attacker-controlled JS that can do its own fetch()).
  - GCP: `http://metadata.google.internal/computeMetadata/v1/` (requires
    `Metadata-Flavor: Google` header — same header-control caveat applies)
  - Azure: `http://169.254.169.254/metadata/instance?api-version=2021-02-01`
    (requires `Metadata: true` header)
- **Internal service pivoting**: Redis (`gopher://` protocol smuggling to
  issue raw commands), internal admin panels, Kubernetes API server
  (`https://kubernetes.default.svc`), internal Jenkins/Grafana/Consul.
- **Protocol smuggling via `gopher://` / `dict://`**: craft raw
  bytes to speak arbitrary text protocols (Redis, Memcached, SMTP) through
  an HTTP-fetching primitive.
- **Blind SSRF confirmation**: DNS-only OAST callback when full HTTP
  interaction isn't reflected; time-based confirmation (compare request
  latency for a reachable vs. unreachable internal IP) when even DNS is
  blocked.

## Bypass (of naive filters)
- **IP encoding**: decimal (`http://2130706433/`), octal
  (`http://0177.0.0.1/`), hex (`http://0x7f000001/`), IPv6
  (`http://[::1]/`, `http://[::ffff:127.0.0.1]/`), short-form
  (`http://127.1/`).
- **DNS rebinding**: register a domain whose A record you control and can
  flip between a benign IP (passes the check-time validation) and
  169.254.169.254/internal IP (used at request-time) — defeats
  "resolve-then-validate-then-fetch-again" implementations that don't
  pin the resolved IP.
- **Redirect-based bypass**: submit an attacker-controlled URL that
  passes the allowlist, which then issues a 3xx redirect to the real
  internal target — effective against validators that only check the
  *initial* URL and not the final resolved destination (many libraries
  follow redirects by default without re-validating).
- **URL parser confusion / differentials**: exploit inconsistencies
  between the validating parser and the fetching library, e.g.
  `http://expected.com@169.254.169.254/`,
  `http://169.254.169.254#@expected.com`,
  `http://expected.com\@169.254.169.254`, backslash vs. forward-slash
  handling, or `http://[email protected]/@169.254.169.254`-style tricks
  when frameworks disagree about the authority component. Also whitespace
  / unicode "fullwidth" characters that survive one parser's regex but not
  the other's.
- **Domain allowlist bypass**: subdomain takeover of an allowlisted domain,
  or if the check is substring-based, register `evil-expected.com` or
  `expected.com.evil.com`.
- **Scheme confusion**: some validators only check `http(s)://` and miss
  `file://`, `gopher://`, `dict://`, `ftp://`, or the fetching library's own
  scheme-specific quirks.
- **CIDR/allowlist off-by-range**: cloud metadata sometimes reachable via
  IPv6 link-local equivalents or alternate documented IPs
  (e.g. `fd00:ec2::254` for AWS IMDSv2 dual-stack) that a v4-only filter
  misses.

## Automation
- `nuclei -tags ssrf` for known-vulnerable software patterns; but most
  real SSRF is business-logic-specific, so manual parameter discovery
  (Arjun, ffuf on param names, or reading client-side JS for
  webhook/import features) plus OAST correlation is the actual workflow.
- Automate the IP-encoding bypass matrix (a short wordlist of
  representations of 127.0.0.1 / 169.254.169.254) against every discovered
  URL-input parameter, each pointing to a *uniquely-tagged* OAST
  subdomain so hits can be attributed to the exact parameter/encoding
  that worked.

## Detection
- Egress-only proxy allowlisting outbound destinations (what the Trello
  bug-bounty testing in this session's transcript observed: "Proxy
  response (403) !== 200 when HTTP Tunneling" — a forward-proxy
  enforcing destination allowlists at the network layer, independent of
  application-level URL validation. This is one of the more robust
  mitigations because it doesn't rely on parsing the URL correctly at
  all).
- WAF/IDS signatures on `169.254.169.254`, `metadata.google.internal`,
  `gopher://` in request bodies.
- Anomalous outbound connection graphs (app server suddenly talking to
  internal management ports it's never touched before).

## Mitigation
- Never do "validate string, then fetch" — resolve the DNS once, validate
  the resulting IP, then connect to that pinned IP (don't re-resolve).
- Enforce network-layer egress control (deny-by-default forward proxy)
  as the primary control, not application-layer string validation, which
  is inherently a parser-differential arms race.
- Disable following redirects for outbound server-side fetches, or
  re-validate the destination on every hop.
- Use IMDSv2 (AWS) / require metadata-flavor headers and disable v1
  entirely; better yet, don't grant the fetching service's IAM role any
  meaningful metadata access it doesn't need.

## Variant Hunting
- Any place a URL, hostname, or "callback"/"webhook"/"import"/"fetch
  preview" concept exists in a product often has a *sibling* endpoint
  with weaker validation (e.g. webhook creation is hardened, but a
  separate "test this webhook" button uses a different code path that
  wasn't updated). Enumerate every feature that plausibly makes an
  outbound request, not just the obvious one.
- Check mobile app APIs and internal/admin APIs separately — SSRF
  protections are frequently only applied to the consumer-facing web
  code path.

## Related CVEs
- CVE-2021-21972 (VMware vCenter SSRF → RCE via vROps plugin)
- CVE-2019-5418 / Rails file-disclosure-via-SSRF-adjacent (Rails `Accept`
  header + `render file:`)
- CVE-2023-28432 (MinIO information disclosure, SSRF-adjacent info leak)
- Capital One breach (2019) — SSRF against AWS WAF-fronted app → IMDSv1
  credential theft → S3 exfiltration (the canonical real-world case study
  for why IMDSv2 exists).

## Related Bug Bounty Reports
- Numerous H1 Hacktivity SSRF-via-webhook reports across SaaS platforms
  (Slack, Shopify app platforms, HubSpot) — pattern: OAuth app /
  integration "test connection" features.
- PDF-export SSRF chains (wkhtmltopdf / headless Chrome SSR) are a
  recurring high-value class because the renderer often executes
  attacker HTML/JS server-side, giving `fetch()`-level control including
  custom headers — directly enabling IMDSv2.

## Related Research
- PortSwigger Web Security Academy — SSRF chapter (canonical bypass
  matrix reference).
- Orange Tsai's "A New Era of SSRF" (Black Hat) — URL parser
  differential attacks, foundational for the "parser confusion" bypass
  class above.

## Practical Hunting Tips
- Grep client-side JS bundles for `webhook`, `callback`, `import`,
  `proxy`, `fetch`, `preview`, `unfurl`, `screenshot`, `render` — these
  are the feature names most likely to hide a server-side fetch.
- Always test with a *uniquely tagged* OAST domain per parameter so
  blind findings are attributable later even if you test many params in
  one sitting.
- When a target's forward-proxy blocks obvious internal IPs, don't stop —
  test the *redirect* bypass, since proxy allowlisting often only
  inspects the first hop's destination, not the final one after a 3xx.

## Real World Examples
- Capital One (2019): SSRF → IMDSv1 → S3 breach, ~100M records.
- Session transcript case study (this KB, 2026-09-03): Trello webhook
  creation endpoint was tested against `127.0.0.1`, `169.254.169.254`,
  decimal/hex/octal-encoded loopback, `localhost`, IPv6 `[::1]`, and
  IPv4-mapped IPv6 — all seven variants were uniformly rejected at the
  proxy layer with an identical `VALIDATOR_URL_NOT_REACHABLE` /
  `Proxy response (403)` error, while a legitimate public URL succeeded.
  This is a good example of network-layer egress control being robust
  against the entire IP-encoding bypass class in one shot, and a
  reminder that a *uniform* rejection across many encodings is itself
  informative — it strongly suggests proxy-layer IP-based blocking
  rather than app-layer string matching (the latter tends to have
  inconsistent per-encoding results).

## References
- PortSwigger SSRF Academy: https://portswigger.net/web-security/ssrf
- OWASP SSRF Prevention Cheat Sheet
- AWS IMDSv2 documentation
