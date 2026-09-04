# LLM Agent Code-Execution Sandbox Escape

## Summary
AI products let the model write and run code — ChatGPT's Code
Interpreter, Claude's Code Execution/Bash tool and Claude Cowork's local
VM, or a Jupyter kernel behind an open-source agent framework — inside an
isolated container/VM so a malicious or model-hallucinated command can't
touch the host or other tenants. This file covers the **execution
layer**: whether that isolation boundary holds, and whether the
sandbox's *permitted* capabilities (especially network egress) can be
abused to exfiltrate data even without a true escape. Distinct from
`ai-security/prompt-injection.md` (how an attacker gets the agent to
*decide* to run attacker-chosen code — usually the trigger for the chains
below) and `ai-security/mcp-tool-poisoning.md` (a reasoning-layer
trust-boundary attack with no code execution involved). SSRF-from-sandbox
is the same root cause/impact as classic server-side SSRF
(`web-security/ssrf.md`, `web-security/cloud-metadata-ssrf-misconfig.md`)
— only the trigger differs (an AI code tool instead of a web app feature).

## Root Cause
- **Generic container/VM misconfiguration**: excess capabilities,
  privileged containers, exposed Docker socket, host paths mounted
  read-write, shared kernel between tenants, unpatched runc/kernel CVEs
  — AI vendors running plain Docker inherit the whole existing
  container-escape catalog with no AI-specific novelty required.
- **Network egress treated as lower-risk than it is**: vendors block
  outbound HTTP/TCP but leave DNS resolution open (tunneling), or
  allowlist a first-party domain that itself accepts
  attacker-influenceable writes under a substituted credential.
- **Egress-policy logic bugs**, not just missing policy: a hostname
  filter and the OS resolver disagreeing on where a hostname ends
  (null-byte confusion), or a "block all outbound" setting silently
  parsed as allow-all.
- **Agent-tooling primitives breaking the boundary while the container
  itself is fine**: git worktree creation, workspace symlinks, or
  shell-init file sourcing chained to execute outside the sandbox even
  when the underlying isolation technology is sound.
- **Full-host mounts for local/desktop execution modes** collapse the
  isolation boundary outright for convenience. Indirect prompt injection
  is overwhelmingly the delivery mechanism that gets the agent to
  *choose* to run the exfiltration/escape code in the first place — the
  sandbox exists to contain the blast radius once that happens.

## Attack Flow
1. Attacker gets instructions into the agent's context, usually via
   indirect prompt injection from a document, page, or tool output.
2. The agent executes code in its sandbox: reads local sandbox state
   (chat history, uploaded files), then acts on whatever network/
   filesystem primitives are actually available.
3. Depending on what the sandbox restricts, the attacker either
   exfiltrates via a *permitted* channel (DNS, an allowlisted API, a
   rendered markdown/image URL) with no escape needed, or chains a
   misconfiguration/logic bug to escape the container/VM and reach the
   host or other tenants.
4. Data lands in attacker infrastructure with no user confirmation,
   since the whole flow executes inside a tool call users rarely audit
   line-by-line.

## Exploitation
- **DNS-tunneling exfiltration** (ChatGPT, Check Point Research): HTTP/
  TCP egress was blocked but DNS resolution stayed open; data was
  encoded as subdomains of an attacker domain and exfiltrated as
  queries, and because the channel is bidirectional, attacker-controlled
  responses relayed commands back in — a slow remote shell built purely
  from DNS.
- **"Claude Pirate" Files-API abuse** (Johann Rehberger / Embrace The
  Red): Claude Code Interpreter's default egress policy allowlists
  `api.anthropic.com` for legitimate use; indirect injection had Claude
  write sensitive context to a sandbox file, then call the Files API
  with an **attacker-supplied API key** embedded in the injected
  content, uploading up to ~30MB to the attacker's own account entirely
  from inside the allowlisted domain.
- **Markdown/image-render exfiltration** (Rehberger, ChatGPT plugins):
  the model emits a markdown image tag whose URL embeds exfiltrated
  data as a query string; the client auto-fetches it to render, leaking
  data with no sandbox bug at all — only that the client treats
  model-generated URLs as safe to fetch.
- **Egress-policy logic bugs** (Aonan Guan, Claude Code CLI): a "block
  all outbound" setting silently parsed as allow-everything
  (CVE-2025-66479), and a SOCKS5 hostname null-byte issue where a
  `*.google.com` allowlist filter matched
  `attacker-host.com\x00.google.com` on the trailing string while the OS
  truncated at the null byte and connected to the attacker's host.
- **Agent-tooling chain to unsandboxed execution** (CVE-2026-55607,
  Claude Code worktree escape): a malicious repo mimicking a `.git`
  directory exploited a worktree-name validation gap (worktree named
  `.git`), symlink-following worktree creation, and a `core.fsmonitor`
  hook to overwrite `~/.zshenv` — sourced by the shell *before* sandbox
  restrictions apply on the next Bash call.
- **Local-VM host-filesystem escape** ("SharedRoot", Claude Cowork,
  Accomplish AI): Cowork's local mode mounted the entire host filesystem
  read-write into its Linux VM; a chained Linux kernel bug
  (CVE-2026-46331, a traffic-control "pedit COW" issue) gave guest-root
  and read/write access anywhere on the host Mac.

## Bypass
- Blocking HTTP/TCP while leaving DNS open is bypassed wholesale by
  tunneling — any outbound resolution must be treated as a data channel.
- Domain allowlists are bypassed when the allowlisted destination
  itself accepts attacker-influenceable writes under a substituted
  credential — allowlisting restricts destination, not what can be
  smuggled to it.
- Hostname filters are bypassed by a parser mismatch between the
  filter's string matching and the OS resolver's actual truncation
  behavior.
- Config-flag semantics bugs (deny silently resolving to allow-all)
  bypass every downstream egress rule at once, regardless of how well
  any individual rule is written.
- Sandbox boundaries built from application-level primitives (worktree
  names, symlinks, shell-init ordering) are bypassed by finding any
  point where those primitives execute before or outside container-level
  enforcement — no container control was positioned to catch the
  worktree chain.

## Automation
- **SandboxEscapeBench** (UK AI Security Institute, arXiv 2603.02277):
  18-scenario benchmark (orchestration, Docker-socket/capabilities/runc,
  kernel/cgroup/eBPF) run inside a container-in-VM harness; frontier
  models (GPT-5, Claude Opus 4.5) reliably exploit difficulty-1/2
  misconfigurations at ~$1/attempt, ~40% success on difficulty-3, 0% on
  kernel-exploit-level 4-5. No zero-days found — every success used a
  documented CVE or known misconfiguration, though models opportunistically
  found unintended paths (e.g. default Vagrant SSH credentials).
- **Comparative sandbox-engine methodology** (arXiv 2606.08433): a
  per-engine checklist — enumerate capabilities/syscalls, probe timing/
  shared-memory side channels between tenants, enumerate mounted
  filesystem paths, verify actual (not documented) egress scope, track
  CVE history/patch cadence as a maintenance-quality proxy.
- Practical recon sequence: `cat /proc/self/status` for unexpected
  `CapEff`/`CapBnd`; check `mount`/`/proc/mounts` for host paths mounted
  read-write; resolve DNS to an attacker domain and test for a response
  back-channel; probe `169.254.169.254` and RFC1918 ranges; try to reuse
  file paths/state across two sessions to test for cross-session
  pooling; diff actually-reachable domains against documented allowlist
  scope — the two have repeatedly diverged in every case above.

## Detection
- Log egress at the sandbox network-namespace boundary, not just
  application-layer HTTP — DNS tunneling is invisible to anything that
  only inspects HTTP/TCP payloads.
- Anomaly-detect on DNS query volume/entropy from sandbox namespaces;
  high-entropy subdomains to one unfamiliar domain is a strong signal.
- Monitor first-party allowlisted API calls (Files API, package
  registries) from inside a sandbox for credentials that don't match
  the invoking user's own session.
- Audit sandbox-session lifecycle for filesystem/process state that
  persists or overlaps across different users/sessions.
- Runtime behavior monitoring for any file/syscall access outside the
  declared sandbox namespace, independent of which specific
  misconfiguration enabled it — the same criterion SandboxEscapeBench
  itself uses to score a successful escape.

## Mitigation
- Default outbound network to fully disabled where the task doesn't
  need it; where egress is required, allowlist by destination *and*
  verify the destination can't relay attacker-controlled data under a
  substituted credential.
- Force DNS through a controlled resolver subject to the same
  allowlist/anomaly checks as HTTP egress, rather than leaving
  resolution unrestricted.
- Null-route cloud metadata IPs (169.254.169.254 and equivalents) at
  the network-namespace/iptables level, not just application-layer
  filtering — agent-generated code can talk to the network stack
  directly.
- Ephemeral, single-use sandboxes destroyed after each session, never
  pooled across users, to remove cross-session leakage as a class.
- Prefer microVM isolation (Firecracker) or userspace-kernel
  interception (gVisor) over plain Docker/runc for untrusted
  model-generated code; treat plain container isolation as insufficient
  by default for this workload.
- Fail closed and test config-parsing (verify a block setting actually
  blocks, and that the egress filter's hostname parsing matches whatever
  library ultimately opens the socket).
- Treat agent-specific tooling (worktree/workspace management, shell
  profile sourcing) as part of the sandbox trust boundary; never
  bind-mount the full host filesystem read-write into a local agent VM
  by default.

## Variant Hunting
- Any "code execution," "data analysis," or "computer use" AI feature
  is a candidate for this class — test DNS as a channel even when HTTP/
  TCP appear fully blocked.
- Any first-party API on a vendor's own egress allowlist is worth
  testing for attacker-credential substitution — generalizes past the
  Anthropic Files API case.
- Any local/on-device execution mode deserves independent review for
  full host-filesystem exposure via convenience bind mounts; don't
  assume cloud-mode hardening carries over.
- Open-source agent frameworks that shell out to Docker without a
  hardening layer are default-vulnerable to the generic container-escape
  catalog — Microsoft's May 2026 research on RCE in agent frameworks
  indicates this is broad, not isolated.
- Re-test previously fixed sandbox bypasses after new agent-tooling
  features ship — both real Claude Code CVEs here were introduced by
  convenience features layered on an otherwise-sound isolation
  primitive, not by the container/VM technology regressing.

## Related CVEs
- CVE-2026-55607 / GHSA-7835-87q9-rgvv — Claude Code CLI git-worktree
  path-confusion chain to unsandboxed shell execution. CVSS 7.7, fixed
  in 2.1.163 (June 2026).
- CVE-2025-66479 — Claude Code CLI sandbox, "block all outbound" parsed
  as allow-all. Fixed Nov 26, 2025.
- CVE-2026-46331 — Linux kernel traffic-control "pedit COW" bug, chained
  by the Claude Cowork researchers to guest-root as the second stage
  after the full-filesystem-mount misconfiguration.
- CVE-2024-21626 — runc working-directory container escape; the
  representative generic CVE any AI vendor on plain Docker/runc
  inherits, with no AI-specific novelty required.
- No public CVE was found for the ChatGPT DNS-tunneling exfiltration
  (Check Point) or the SOCKS5 null-byte egress bypass (Aonan Guan) —
  both were disclosed/patched without an assigned identifier as of this
  pass; cited via their primary writeups rather than an invented ID.

## Related Bug Bounty Reports
- Johann Rehberger → Anthropic HackerOne, "Claude Pirate" Files-API
  exfiltration, disclosed Oct 25 2025; closed as out-of-scope
  ("model safety issue"), reversed Oct 30 2025 — a useful case study in
  vendor triage friction over "sandbox exfiltration vs. alignment issue."
- Aonan Guan → Anthropic, two Claude Code sandbox egress bypasses
  (CVE-2025-66479; SOCKS5 null-byte), both accepted and patched.
- Metnew → Anthropic, Claude Code worktree sandbox escape
  (CVE-2026-55607), $3,700 bounty + $50 retest, full write-up on GitHub.
- Accomplish AI (Oren Yomtov, Or Hiltch) → Anthropic, Claude Cowork
  "SharedRoot" local-VM escape; closed without a direct code fix,
  mitigated by defaulting Cowork to cloud execution.

## Related Research
- SandboxEscapeBench (arXiv 2603.02277) — nested-sandbox benchmark;
  frontier models cheaply exploit real-world-plausible
  misconfigurations, no zero-days found in this evaluation.
- "The Balkanization of Execution-Security Research for AI Coding
  Agents" (arXiv 2607.05743) — isolation/access-control/TOCTOU survey
  specific to AI coding agents.
- "AI Code Sandboxes: A Comparative Security Study, Part 1"
  (arXiv 2606.08433) — engine-level comparative methodology.
- "AgentBound" (FSE 2026, arXiv 2510.21236) and "Lingering Authority"
  (arXiv 2606.22504) — capability-revocation defenses for bounding what
  an agent's execution environment can do after grant time.
- Microsoft Security Blog, "When prompts become shells: RCE
  vulnerabilities in AI agent frameworks" (May 2026).
- See also `ai-security/prompt-injection.md` (the trigger for nearly
  every chain above) and `ai-security/mcp-tool-poisoning.md` (a parallel
  reasoning-layer trust failure with no code execution involved).

## Practical Hunting Tips
- Test DNS resolution as an exfiltration/command channel explicitly,
  even when outbound HTTP/TCP is documented as fully blocked — the
  single most-repeated gap across real findings.
- Enumerate every domain on a sandbox's network allowlist and test
  whether any accept writes/uploads under attacker-supplied credentials.
- Test hostname-filtering egress with null-byte and other
  parser-confusion payloads (`allowed-suffix.com\x00attacker.com`).
- For local/on-device execution modes, check `mount`/`/proc/mounts`
  first — full host-filesystem bind-mounts for convenience are a repeat
  pattern and often the highest-impact finding available.
- Frame a sandbox-egress finding explicitly as a security/data-
  exfiltration bug with a concrete data-loss scenario, not as a "model
  did something it shouldn't" alignment note — vendor triage history
  shows this class can initially get misclassified as out-of-scope.

## Real World Examples
All six incidents in Exploitation above are real, disclosed 2025-2026
findings against production AI products (ChatGPT Code Interpreter and
Claude Code/Cowork), not hypotheticals — see Related CVEs and Related
Bug Bounty Reports for identifiers, dates, and outcomes. Notably, the
Claude Code CLI's two independent egress-policy bugs were live for
roughly six months (Oct 2025 sandbox launch to April 2026 fix), and the
Cowork "SharedRoot" mount issue affected an estimated ~500,000 macOS
users running local execution mode before Anthropic mitigated it by
defaulting to cloud execution.

## References
- https://research.checkpoint.com/2026/chatgpt-data-leakage-via-a-hidden-outbound-channel-in-the-code-execution-runtime/
- https://embracethered.com/blog/posts/2025/claude-abusing-network-access-and-anthropic-api-for-data-exfiltration/
- https://embracethered.com/blog/posts/2023/chatgpt-webpilot-data-exfil-via-markdown-injection/
- https://www.theregister.com/security/2026/05/20/even-claude-agrees-hole-in-its-sandbox-was-real-and-dangerous/5243662
- https://www.securityweek.com/anthropic-silently-patches-claude-code-sandbox-bypass/
- https://github.com/Metnew/write-ups/tree/main/claude-code-worktree-sandbox-escape
- https://thehackernews.com/2026/07/claude-cowork-flaw-could-let-ai-agent.html
- https://arxiv.org/html/2603.02277v1
- https://arxiv.org/pdf/2607.05743
- https://arxiv.org/pdf/2606.08433
- https://www.microsoft.com/en-us/security/blog/2026/05/07/prompts-become-shells-rce-vulnerabilities-ai-agent-frameworks/

---
*Added 2026-09-04 via research pass.*
