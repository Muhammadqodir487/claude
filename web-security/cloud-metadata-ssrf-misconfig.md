# Cloud Misconfiguration & Metadata-Service SSRF (AWS/Azure/GCP/K8s)

## Summary
Cloud environments concentrate an enormous amount of trust into a
handful of predictable patterns — a well-known metadata endpoint IP
address, a predictable storage-bucket naming convention, an over-broad
IAM role — and 2026's threat landscape confirms these remain the
dominant real-world path to full account compromise, not novel exploit
techniques. This file focuses on the two highest-yield patterns for
bug bounty/pentest work: SSRF-to-metadata-credential-theft, and public
storage/permutation-scanning misconfiguration discovery. See also
`web-security/ssrf.md` for the general SSRF root cause and
`ai-security/mcp-supply-chain-attacks.md` for the ML/AI-tooling
intersection of this same pattern.

## Root Cause
- **Cloud metadata services trust network origin, not identity**: AWS
  (`169.254.169.254`), GCP, and Azure Instance Metadata Service (IMDS)
  all serve temporary credentials/secrets to *any* request originating
  from the instance's own local network stack — any application on that
  instance that can be coerced into making an arbitrary outbound HTTP
  request effectively has a path to those credentials, regardless of
  the application's own authentication model.
- **TOCTOU in URL-validation-then-follow-redirect patterns**: validating
  a webhook/callback URL once at registration time (confirming it
  resolves to a public IP) is not equivalent to validating what the
  request actually reaches at *trigger* time — if the validated URL
  later responds with an HTTP redirect to an internal address, and the
  HTTP client library follows redirects by default, the validation step
  is completely bypassed.
- **Predictable cloud-resource naming**: S3 buckets, Azure Blob
  containers, and GCS buckets frequently follow guessable conventions
  (company name + environment + purpose), making them discoverable via
  permutation scanning even with no direct link ever published.
- **Over-permissioned IAM as the default, not the exception**: cited as
  affecting the vast majority of cloud accounts in 2026 industry
  reporting — a role created for one narrow task frequently retains
  broad standing permissions because least-privilege scoping is treated
  as optional hardening rather than a default requirement.

## Attack Flow
1. Identify any application feature that makes a server-side HTTP
   request based on user/attacker-influenced input: webhook
   registration/testing, URL preview/unfurling, PDF/image
   generation-from-URL, "import from URL" features, and (per the 2026
   MLOps-specific pattern) ML experiment-tracking/webhook-test
   endpoints.
2. Test whether URL validation happens once (at registration/save time)
   versus every time the request is actually made — register a URL you
   control, confirm it passes validation, then have your controlled
   server respond with a 302/301 redirect to `169.254.169.254` (or the
   GCP/Azure metadata equivalent) and see if the redirect is followed.
3. If the response is reflected back to the caller (a "full-read" SSRF,
   as opposed to blind), directly read the metadata response containing
   temporary IAM credentials.
4. Separately, and independent of any application bug: enumerate
   predictable storage-bucket names for the target (company name +
   common suffixes: `-backup`, `-prod`, `-staging`, `-assets`, `-data`)
   across all three major providers, checking each for public
   list/read/write permissions.

## Exploitation
- **CVE-2026-64849 (MLflow, CVSS 9.3)**: unauthenticated SSRF via the
  webhook-test endpoint (`POST /api/2.0/mlflow/webhooks/{id}/test`).
  `_validate_webhook_url` checks the URL resolves to a public IP *at
  registration time only*; the actual test/trigger request uses a
  redirect-following HTTP client, so an attacker registers a webhook
  pointing to their own server, which responds with a redirect to
  `169.254.169.254` (or `127.0.0.1` for internal-service access). The
  endpoint reflects the upstream response's status and body back to the
  caller — a full-read SSRF, directly exposing AWS IAM tokens, GCP
  service-account keys, or Azure Managed Identity tokens in the
  response. Under active exploitation by financially-motivated actors
  running automated scans against internet-facing MLflow Tracking
  Servers specifically to harvest cloud credentials for resale. Fixed
  in MLflow 3.15.0.
- **Storage-permutation discovery**: scanning generated bucket-name
  candidates against AWS S3, Azure Blob, and GCS simultaneously (a
  target's cloud footprint is rarely single-vendor) — a purely passive/
  read-only technique (checking existence and public-read status)
  until an actual misconfigured bucket is confirmed.

## Bypass
- **Redirect-based validation bypass** generalizes far beyond MLflow's
  specific webhook feature: any "validate once at save time" pattern
  applied to a URL that's later *fetched* rather than just stored is
  vulnerable to the identical TOCTOU class — register/save a benign
  URL, have it redirect to an internal target at actual-fetch time.
- DNS-rebinding is the classic variant of the same underlying pattern
  when validation resolves a hostname once and the fetch re-resolves it
  later — same root cause (check and use split into separate, re-
  exploitable steps), different mechanism (DNS TTL manipulation instead
  of HTTP redirect).

## Automation
- Cloud-footprint mapping: enumerate the target's presence across AWS,
  GCP, and Azure simultaneously rather than assuming single-vendor,
  since most real organizations run genuinely multi-cloud or have
  historical resources on a provider they've since "migrated away from"
  (and forgotten to decommission).
- Bucket-name permutation tooling generating candidates from company
  name + common environment/purpose suffixes, checked read-only against
  all three providers' public APIs.
- For webhook/callback-URL features specifically: script a redirect-
  chain test harness (register → trigger → observe) as a standard check
  item any time such a feature is found, given how repeatedly this
  exact TOCTOU pattern recurs across unrelated products.

## Detection
- Egress monitoring specifically for outbound requests from application
  servers to `169.254.169.254` or other cloud metadata IPs that don't
  match the expected internal SDK/agent process — an application-level
  process making this request via its own HTTP client library (rather
  than the cloud SDK) is a strong signal of active SSRF exploitation.
- IMDSv2 (AWS) enforcement (session-oriented, token-based metadata
  access rejecting simple GET requests) closes the *specific* MLflow-
  style exploitation path even if the application-level SSRF bug
  remains — a strong compensating control independent of fixing every
  individual application.
- Public-bucket monitoring: continuous automated re-scanning of an
  organization's own known and permutation-discoverable bucket names for
  a public-access-policy drift, since misconfiguration frequently
  reappears after being fixed once (a new deploy resets an ACL, a new
  team recreates a similarly-named bucket without the original's
  hardening).

## Mitigation
- **Re-validate URLs at the point of use, not just at registration**:
  any webhook/callback/URL-fetch feature must re-check the resolved
  destination immediately before the actual outbound request, and must
  either disable redirect-following entirely for these requests or
  re-validate the redirect target with the same rigor as the original
  URL.
- **Enforce IMDSv2 / equivalent token-based metadata access** on every
  cloud compute instance as a standing platform-level control,
  independent of any single application's SSRF-safety — this converts a
  simple GET-based SSRF into one requiring a much harder-to-achieve
  PUT-based token-fetch step first.
- Default to least-privilege IAM scoping per workload rather than broad
  standing roles, so that even a successful credential theft via SSRF
  yields minimal blast radius.
- Enforce private-by-default bucket policies at the organization level
  (e.g., AWS S3 Block Public Access as an account-wide setting) rather
  than per-bucket opt-in, so a single misconfigured bucket creation
  doesn't default to public.

## Variant Hunting
- Any feature accepting a URL for later server-side use (webhooks, SSO
  metadata URLs, "import from," avatar-from-URL, PDF rendering from a
  provided link) is a candidate for the identical registration-time-
  only-validation TOCTOU pattern MLflow demonstrated — check each one
  independently, since a fix in one feature of a product doesn't imply
  the same team fixed a structurally identical feature elsewhere in the
  same codebase.
- Any self-hosted MLOps/data-tooling product (experiment trackers,
  model registries, data-pipeline orchestrators — mirroring the DevOps-
  tool exposure pattern in `bug-bounty/methodology.md`) is worth
  checking specifically for this class, since MLOps tooling as a
  category has had comparatively less security scrutiny than mainstream
  web frameworks while frequently running with direct cloud-credential
  access by design.

## Related CVEs
- CVE-2026-64849 — MLflow, CVSS 9.3, unauthenticated SSRF via webhook-
  test redirect bypass, CISA KEV (added 2026-08-19), full-read
  cloud-credential exposure.

## Related Bug Bounty Reports
- (Populate with specific disclosed cloud-metadata-SSRF or bucket-
  misconfiguration reports as found — these are extremely common in
  HackerOne Hacktivity under "SSRF" and "Information Disclosure" tags.)

## Related Research
- Vectra AI — "What Are Cloud Misconfigurations?"
- Shattered.io — MLflow SSRF (CVE-2026-64849) and cloud IAM
  misconfiguration industry-scale reporting (98% of accounts affected by
  some IAM misconfiguration, 2026).
- ToxSec (Medium) — "A Bug Bounty Hunter's Guide to Cloud
  Misconfiguration."

## Practical Hunting Tips
- For any webhook/callback feature, always test the full
  register-then-trigger lifecycle, not just whether the registration
  step validates correctly — the MLflow case shows the vulnerability is
  entirely in the *gap* between those two steps, invisible if you only
  test one of them.
- Don't assume single-cloud-vendor scope — run bucket-name permutation
  checks against AWS, Azure, and GCP simultaneously for every target,
  since multi-cloud (deliberate or accidental via M&A/team sprawl) is
  now the norm rather than the exception.

## Real World Examples
- CVE-2026-64849 (MLflow) — actively exploited at internet scale by
  financially-motivated actors specifically harvesting cloud credentials
  from exposed MLflow Tracking Servers.

## References
- https://www.ionix.io/threat-center/cve-2026-64849/
- https://shattered.io/mlflow-ssrf-cve-2026-64849-cisa-kev/
- https://shattered.io/cloud-iam-misconfiguration-litellm-breach-2026/
- https://medium.com/@cocopelly255/a-bug-bounty-hunters-guide-to-cloud-misconfiguration-522db28ff93e

---
*Added 2026-09-04 via research pass.*
