# MCP & AI-Agent Supply Chain Attacks

## Summary
As agentic AI tooling matured through 2025-2026, the Model Context
Protocol (MCP) ecosystem and the broader AI-agent-framework dependency
chain (PyPI/npm packages that agent frameworks pull in) became a live
supply-chain attack surface — distinct from prompt injection, but often
chained with it: a compromised MCP server or library doesn't need to
"trick" the model at all if it can just directly exfiltrate data or run
code from inside a component the agent already trusts.

## Root Cause
- MCP servers are typically installed/trusted based on name/popularity,
  not code review, and can ship a clean version history before adding
  malicious behavior in a later, easy-to-miss update — the same
  "reputation laundering" pattern as classic npm/PyPI supply-chain
  attacks, just applied to a newer package ecosystem with less mature
  vetting norms.
- Core MCP infrastructure libraries, used transitively by huge numbers of
  downstream agent tools, are high-value targets: a single RCE there
  compromises every agent built on top of it.
- AI agent framework "gateway" packages (e.g., LLM-provider routing
  libraries) sit in a privileged position — they see every prompt and
  every model response for every framework that depends on them.

## Attack Flow
1. Attacker publishes (or compromises) a package that looks legitimate —
   either a new MCP server with a plausible use case, or by taking over
   a popular existing package/maintainer account.
2. Package behaves correctly for a period (sometimes many versions) to
   build trust/downloads before the malicious payload ships.
3. Malicious update adds a small, easy-to-overlook change: a single line
   of exfiltration code, a backdoored dependency pin, or a code-execution
   path triggered by a specific crafted input.
4. Because the package is already integrated into agent workflows with
   real tool-calling/data access, the payload activates with the
   privileges the agent already has — no separate prompt-injection step
   needed.

## Exploitation
- **Malicious MCP server ("tool poisoning" via distribution, not just
  description text)**: `postmark-mcp` shipped fifteen clean versions
  before quietly adding a single line of exfiltration code — a
  documented first-in-the-wild case of an openly-malicious MCP server
  reaching real users. (Kagi/community security research, reported
  2026.)
- **RCE in core MCP infrastructure**: CVE-2025-6514, CVSS 9.6, a remote
  code execution flaw disclosed in core MCP infrastructure used by
  hundreds of thousands of developers — the severity/reach combination
  (widely-depended-on infra + full RCE) makes this one of the most
  significant MCP-ecosystem CVEs to date.
- **AI-gateway library backdoor**: a backdoor was live on PyPI for
  roughly three hours in March 2026 in a compromised update to
  **LiteLLM** — the language-model gateway used by CrewAI, DSPy,
  Microsoft GraphRAG, and dozens of other agent frameworks. Despite the
  short window, ~47,000 downloads occurred before removal, illustrating
  how fast automated CI/CD dependency pulls can distribute a compromised
  package before human review catches it.

## Bypass
- Same techniques as classic software supply-chain attacks apply
  (typosquatting package names, compromising maintainer credentials,
  dependency confusion between internal/public package registries) —
  MCP/agent-framework ecosystems don't yet have materially different
  defenses than npm/PyPI did when these attack classes matured there.
- Trust signals agents/developers actually use today (star count,
  download count, "verified" badges on marketplaces) are exactly the
  signals a patient attacker can farm before flipping to malicious
  behavior — clean version history is not evidence of safety.

## Automation
- Dependency-pinning + lockfile diff review in CI specifically flagging
  *new* MCP server additions or *any* change to a gateway/routing
  library used by an agent stack, treated with the same scrutiny as a
  new production code-execution dependency.
- Runtime allowlisting of what an MCP server/tool is actually permitted
  to do (network egress, filesystem paths) independent of what its
  manifest claims, so a compromised update can't silently gain new
  capabilities without a corresponding infrastructure change that's
  easier to catch than a code diff.

## Detection
- Egress monitoring on agent-hosting infrastructure for connections to
  destinations not present in a known-good baseline — this is how
  exfiltration-via-compromised-dependency tends to surface in practice,
  since the exfiltration traffic itself is the most concrete signal
  (matches the general SSRF/egress-control detection principle in
  `web-security/ssrf.md`).
- Version-pin drift alerts: notify when a dependency updates outside an
  expected cadence/review process, especially for anything in the
  MCP-server or LLM-gateway category.

## Mitigation
- Treat every third-party MCP server as untrusted code with real system
  access, not as a "just an API wrapper" — apply the same review bar as
  you would to a new production dependency with filesystem/network
  access, because that's what it functionally is.
- Least-privilege scoping for MCP servers: only grant the specific
  tool/data access a given task needs, not broad standing access "just
  in case" (mirrors the least-privilege guidance in
  `ai-security/prompt-injection.md`).
- Pin exact versions and review diffs on every update for MCP servers
  and LLM-gateway libraries specifically, rather than auto-upgrading —
  the LiteLLM incident shows the compromise window can be short enough
  that only manual/delayed-update gates would have prevented affected
  installs.

## Variant Hunting
- Any widely-depended-on "glue" library in the agent ecosystem (routing,
  memory/vector-store clients, orchestration frameworks) is a candidate
  for the same class of attack as LiteLLM — audit your agent stack's
  dependency tree for similarly-positioned single points of leverage.
- Re-examine any MCP server your agents already trust for a sudden
  version bump with a disproportionately small diff relative to its
  changelog claims — the `postmark-mcp` pattern (clean history, then one
  quiet malicious line) is specifically designed to not look alarming in
  a routine changelog skim.

## Related CVEs
- CVE-2025-6514 — RCE in core MCP infrastructure, CVSS 9.6.

## Related Bug Bounty Reports
- (Not yet populated — MCP-ecosystem bug bounty programs are still young
  as of 2026; add specific disclosed reports here as they're found via
  future research passes.)

## Related Research
- OWASP 2026 LLM Security Report — reports prompt injection attacks up
  340% year-over-year and situates supply-chain/MCP risk within the
  broader agentic-AI threat model.
- Community write-ups on the `postmark-mcp` incident (search current
  sources at time of reading — this is a fast-moving, recently-reported
  case as of this KB entry's creation date).

## Practical Hunting Tips
- When auditing an agent deployment, list every MCP server and gateway
  library in use, then check each one's *maintainer/publishing history*
  (not just its current code) — a name change, ownership transfer, or a
  long quiet period followed by a sudden update are all worth a closer
  look independent of what the diff itself contains.
- Don't assume "it's just a thin API wrapper" reduces risk — thin
  wrappers are exactly what let a single malicious line hide most
  effectively, since reviewers expect them to be boring.

## Real World Examples
- **postmark-mcp** — malicious MCP server, 15 clean versions then
  quiet exfiltration code addition (2026).
- **LiteLLM PyPI backdoor** — ~3-hour compromise window, ~47,000
  downloads, affecting CrewAI/DSPy/Microsoft GraphRAG and other
  downstream agent frameworks (March 2026).
- **CVE-2025-6514** — CVSS 9.6 RCE in core MCP infrastructure affecting
  hundreds of thousands of developers.

## References
- Help Net Security (2026-06-11): OWASP prompt-injection / agentic AI
  security-failures coverage —
  https://www.helpnetsecurity.com/2026/06/11/owasp-prompt-injection-ai-security-failures/
- arXiv 2607.05120 — "Agent Data Injection Attacks are Realistic Threats
  to AI Agents" — https://arxiv.org/pdf/2607.05120
- arXiv 2604.21477 — "MCP Pitfall Lab: Exposing Developer Pitfalls in MCP
  Tool Server Security under Multi-Vector Attacks" —
  https://arxiv.org/pdf/2604.21477
- arXiv 2603.11088 — "The Attack and Defense Landscape of Agentic AI: A
  Comprehensive Survey" — https://arxiv.org/pdf/2603.11088

---
*Added 2026-09-03 via scheduled research pass.*
