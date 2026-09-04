# Race Conditions (Web & System-Level)

## Summary
A race condition arises whenever a system checks a condition and acts on
it as two separate, non-atomic steps ("time-of-check to time-of-use" /
TOCTOU) — an attacker who can get a second operation to run *between*
the check and the use invalidates the assumption the check was supposed
to guarantee. On the web this classically meant limit-overrun bugs
(coupon reuse, double-spend); James Kettle's 2023-24 research
("Smashing the State Machine") reframed the field around a much larger
class of state-machine race conditions, and 2026 tooling has pushed
network-level race precision down to sub-millisecond even across
continents, while the same root-cause pattern shows up identically in
OS-level security software.

## Root Cause
- **Non-atomic check-then-act sequences**: validate balance/limit/
  ownership, *then* perform the debit/increment/action in a separate
  step, with no locking or atomic operation tying the two together —
  any concurrent second request can interleave between them.
- **Session/state partial-initialization windows**: multi-step flows
  (e.g., email verification, 2FA enrollment) that briefly leave an
  account in a "partially trusted" state create a race window an
  attacker can exploit by hitting a *different* endpoint during that
  window before the flow completes.
- **OS/security-software file-handling TOCTOU**: a privileged process
  validates a file path/property, then performs a privileged operation
  against "the same" resource — if that resource can be swapped out
  (symlink swap, directory-junction redirect) between the two steps,
  the privileged operation acts on attacker-controlled content instead.
- **Network jitter previously masked most race windows**: remote race
  conditions were historically hard to land precisely because ordinary
  network delay variance made simultaneous arrival unreliable — this is
  a tooling/technique problem, not a fix, and 2023-2026 research has
  systematically closed this gap.

## Attack Flow
1. Identify a state-changing operation gated by a limit, balance, or
   one-time-use check (coupon redemption, withdrawal, referral bonus,
   email/phone-number addition subject to a per-account cap, retest/
   payout confirmation).
2. Confirm the check and the act are separate steps by testing whether
   sequential requests behave differently from concurrent ones (a
   sequential test alone will never reveal a race condition — it must
   be tested concurrently).
3. Fire multiple identical (or near-identical) requests as close to
   simultaneously as possible — for HTTP, using the single-packet
   technique (below) to eliminate network-jitter-induced skew — and
   check whether more than the intended number of successful operations
   occurred.
4. For state-machine races beyond simple limit-overrun (per Kettle's
   broader framing): race a state transition against a *different*
   endpoint that reads or depends on the in-flight state, rather than
   only racing the same endpoint against itself.

## Exploitation
- **Single-packet attack (James Kettle / PortSwigger Research)**:
  bundle multiple HTTP/2 requests into a single TCP packet by
  withholding a small final fragment of each request until all are
  queued, then releasing them together — this makes the server receive
  and begin processing all requests within the same packet, eliminating
  network jitter as a variable entirely. Demonstrated squeezing 30
  requests sent from Melbourne to Dublin into a sub-1ms execution
  window — remote race conditions become as reliable as local ones.
  Implemented in Burp Suite Repeater (tab groups) and the open-source
  Turbo Intruder extension.
- **Limit-overrun classics**: racing concurrent requests against a
  coupon-redemption, referral-bonus, or per-account-limit endpoint to
  exceed the intended cap — documented real-world cases include racing
  email-address-addition requests to bypass a per-account limit, and
  racing a bug-bounty *retest confirmation* feature to trigger multiple
  payouts for the same retest.
- **RoguePlanet (CVE-2026-50656)**: a local privilege escalation
  exploiting a TOCTOU race in Microsoft Defender's file-processing path
  — Defender's privileged engine validates a file path, then performs a
  write/remediation against it as a separate step; RoguePlanet redirects
  that second step to a location the attacker controls, spawning a
  SYSTEM-level command prompt. Affected fully patched Windows 10/11
  (including June 2026 cumulative update KB5094126) — a clear
  demonstration that this bug class is not web-specific and can defeat
  even security software's own privileged operations.
- **Sequence-sync extension of single-packet attacks (GMO Flatt
  Security, 2026)**: research extending the single-packet technique
  past HTTP/2's practical request-count ceiling by synchronizing TCP
  sequence numbers, breaking past the ~65,535-byte single-packet size
  limit to scale simultaneous-arrival races to larger request counts.

## Bypass
- Rate limiting keyed only on request *sequence* (e.g., "no more than N
  requests per second") doesn't prevent races where all N-or-fewer
  requests are legitimately allowed individually but the check-then-act
  gap lets more than N succeed when they land concurrently — rate
  limiting and race-condition protection are not the same control.
- Idempotency keys/tokens prevent *retries* of the same logical
  operation but don't automatically prevent a race if the
  idempotency-key check itself has the same non-atomic check-then-act
  structure as the operation it's meant to protect.

## Automation
- **Turbo Intruder** (Burp extension, James Kettle) — the standard
  tool for both classic limit-overrun races and single-packet-attack
  execution at scale.
- Burp Suite's built-in "Send group in parallel" Repeater feature for
  quick manual race testing without needing the full single-packet
  technique for less network-sensitive (e.g., same-datacenter) targets.

## Detection
- Application-level: log and alert on any state-changing operation
  succeeding more times than its stated limit within a short window —
  this is definitionally what a race-condition exploit produces, and is
  detectable purely from business-logic-level audit logs without any
  network-level instrumentation.
- Anomalous request timing clustering (many identical/near-identical
  requests from one client arriving within a sub-millisecond window) is
  itself a strong signal of an active single-packet-attack attempt.

## Mitigation
- Use database-level atomic operations (row locking, atomic
  increment/decrement, unique constraints) for any check-then-act
  sequence gating a limited resource, rather than separate
  read-then-write application code.
- Serialize state-changing requests per user/resource at the
  application layer (e.g., a per-account mutex around the critical
  section) so concurrent requests for the same resource are forced
  through the check-then-act sequence one at a time regardless of
  network-level timing.
- For privileged file-handling operations specifically (per the
  RoguePlanet pattern): operate on a file handle/descriptor obtained
  once and reused for both the check and the act, rather than re-
  resolving a path string between steps — this closes the
  symlink/junction-swap variant of TOCTOU at the OS level.

## Variant Hunting
- Every "resource gated by a per-account/per-time-window limit" feature
  in an application is a race-condition candidate by default — coupon
  codes, referral bonuses, free-trial activations, withdrawal limits,
  vote/like counters, seat/inventory reservations, and — per the 2026
  real-world example — a bug bounty platform's own *retest payout*
  feature.
- Any privileged process anywhere (not just Defender) that separately
  validates-then-acts on a filesystem path is a TOCTOU candidate — this
  is a generic OS-security-software pattern, not a Defender-specific
  bug, worth checking in any AV/EDR/backup-agent file-processing path.
- Beyond limit-overrun: per Kettle's "Smashing the State Machine"
  framing, look for races between a state-machine transition (e.g.,
  "verifying" → "verified") and a *different* endpoint that trusts the
  post-transition state — these are systematically underreported
  relative to simple limit-overrun races because they require modeling
  the whole state machine, not just one endpoint in isolation.

## Related CVEs
- CVE-2026-50656 (RoguePlanet) — Microsoft Defender TOCTOU race, local
  privilege escalation to SYSTEM, affecting fully patched Windows
  10/11; publicly released without coordinated disclosure.

## Related Bug Bounty Reports
- Documented 2026 case: race condition in a bug bounty platform's own
  retest-confirmation feature enabling multiple payouts for a single
  retest (via concurrent retest-confirmation requests).
- Documented case: racing email-address-addition requests to bypass a
  per-account address-count limit.

## Related Research
- James Kettle / PortSwigger Research — "The single-packet attack:
  making remote race-conditions 'local'" and "Smashing the state
  machine: the true potential of web race conditions" (Black Hat USA
  '23 / DEF CON 31).
- GMO Flatt Security Research (2026) — "Beyond the Limit: Expanding
  single-packet race condition with a first sequence sync for breaking
  the 65,535 byte limit."
- Picus Security / CSA Lab Space — RoguePlanet (CVE-2026-50656)
  technical analyses.

## Practical Hunting Tips
- Always test concurrently, never just sequentially fast — a sequential
  "fire requests as fast as possible in a loop" test systematically
  misses races that only manifest with true simultaneous arrival; use
  Turbo Intruder or Burp's parallel-send feature specifically.
- When testing a remote (non-same-datacenter) target, default to the
  single-packet technique rather than a naive parallel-request test —
  network jitter alone can mask a real race condition in a naive test
  and produce a false negative.
- Model the full state machine of a multi-step flow (signup,
  verification, payment, fulfillment) before testing, then race
  transitions *between* steps against reads from other endpoints, not
  just the same endpoint against itself.

## Real World Examples
- CVE-2026-50656 (RoguePlanet) — Microsoft Defender TOCTOU LPE,
  released June 10, 2026, hours after that month's Patch Tuesday, by a
  researcher who cited frustration with Microsoft's bug bounty response
  timelines as the reason for skipping coordinated disclosure.
- Bug bounty retest-payout race condition — multiple payouts triggered
  for a single retest via concurrent confirmation requests.

## References
- https://portswigger.net/research/the-single-packet-attack-making-remote-race-conditions-local
- https://portswigger.net/research/smashing-the-state-machine
- https://flatt.tech/research/posts/beyond-the-limit-expanding-single-packet-race-condition-with-first-sequence-sync/
- https://www.picussecurity.com/resource/blog/rogueplanet-anatomy-of-the-nightmare-eclipse-microsoft-defender-zero-day
- https://www.yeswehack.com/learn-bug-bounty/ultimate-guide-race-condition-vulnerabilities

---
*Added 2026-09-04 via research pass.*
