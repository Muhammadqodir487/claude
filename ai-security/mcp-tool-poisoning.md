# MCP Tool Poisoning (Description-Level Indirect Prompt Injection)

## Summary
Distinct from `ai-security/mcp-supply-chain-attacks.md` (malicious code
shipped in a package/server) — tool poisoning attacks the AI agent's
*reasoning*, not its runtime. It exploits the fact that agents load MCP
tool descriptions, parameter schemas, and even tool *response content*
into the model's context with the same implicit authority as system
instructions, with no validation, sanitization, or integrity check on
that free text. OWASP has codified this as **MCP03:2025** in its MCP Top
10, grouped with rug-pulls and tool shadowing as attacks on the agent's
capability supply chain. See also `ai-security/prompt-injection.md` for
the general indirect-injection pattern this specializes.

## Root Cause
- Architectural, not a patchable implementation bug: MCP tool
  descriptions are natural-language free text, and agents cannot
  reliably distinguish "legitimate operational guidance written by the
  tool author" from "adversarial instructions embedded in the same
  field" — both get the same trust level in the model's context window.
- No cryptographic integrity binding between the tool description a
  human/reviewer approved and the tool description actually loaded at
  session-start time, which is what enables rug-pulls (see below).
- Tool-returned *content* (not just the static description) inherits the
  same elevated trust in most agent implementations — a poisoned API
  response can inject further instructions mid-session, not just at
  tool-registration time.

## Attack Flow
1. Attacker registers a malicious MCP server (or compromises/updates an
   existing trusted one) with a tool description that reads as benign to
   a human skimming it, but embeds imperative instructions aimed at the
   *model*, often concealed via Unicode homoglyphs, zero-width
   characters, or appended after the legitimate-looking description text
   so a quick review doesn't notice it.
2. A user/agent approves the tool based on its apparent (benign)
   function.
3. At the next session, the agent loads the tool description into
   context as trusted operational guidance and follows the embedded
   instructions when the tool is invoked or even just present in
   context — no additional social engineering of the *user* required.
4. Embedded instructions direct the agent to take an unauthorized action
   using capabilities/data it already legitimately has access to
   (exfiltrate repository contents, message history, credentials; invoke
   a *different*, unrelated tool the attacker doesn't control directly).

## Exploitation — Attack Variants
- **Tool description poisoning**: direct instruction injection in the
  metadata/description field itself — the base case above.
- **Rug-pull attacks**: the server changes its tool definitions *after*
  a human already approved the original (benign) version, since most
  clients don't re-validate on every session start — creates persistent
  covert access that survives the initial review entirely.
- **Tool shadowing**: a malicious tool's description contains
  instructions that alter how the agent uses a *different*, legitimate
  tool from another server entirely — the attacker doesn't need to
  control the tool actually being misused, only to be present in the
  same context window as it.

## Bypass
- Concealment techniques defeat manual/visual review specifically:
  Unicode homoglyphs, zero-width spaces, and instruction text appended
  after enough benign-looking content that a reviewer stops reading
  closely.
- Rug-pulls bypass any control that only checks tool definitions *at
  approval time* — the entire attack is designed around the gap between
  one-time human review and every-session automated trust.

## Automation
- `mcp-scan` and similar static analysis tools flag injection-pattern
  language and cross-server shadowing indicators in tool manifests —
  useful as a triage pass, not a complete defense given the architecture-
  level root cause.
- MCPTox (arXiv 2508.14925) is the standard benchmark for measuring
  attack success rate of poisoned tool descriptions against real agents:
  tested against 45 live MCP servers / 353 real tools, popular agents
  showed attack success rates above 60%, peaking at 72.8% — useful as a
  reference point for how effective this class is against current-
  generation agents without specific defenses in place.

## Detection
- Hash-pin tool manifests at approval time (SHA-256 of the full tool
  definition) and automatically re-verify against that hash at every
  session initialization — flags rug-pulls the moment the definition
  changes, independent of whether the change is "obviously" malicious.
- Structured audit logging of every tool definition load and invocation,
  specifically to support after-the-fact incident analysis when
  anomalous agent behavior is noticed downstream rather than caught live.
- Runtime behavioral monitoring for agent actions inconsistent with the
  stated task/prompt — the strongest practical signal given that static
  text analysis of the poisoned description can be arbitrarily obfuscated.

## Mitigation
- Treat tool-returned content as untrusted data, not as elevated-trust
  context, in agent architecture — establish an explicit trust boundary
  so a tool response can't silently gain system-instruction-level
  authority in subsequent reasoning steps.
- Explicit allowlisting of MCP servers rather than open access to public
  registries; require re-review (not silent auto-accept) on *any* change
  to a tool definition, matching the version-pin discipline described in
  `ai-security/mcp-supply-chain-attacks.md`.
- Deploy an MCP gateway/proxy that intercepts and enforces
  policy-consistent tool manifests between the server and the agent,
  rather than trusting whatever a given server sends at connect time.

## Variant Hunting
- Any agent architecture that loads *any* third-party free text into the
  model's context with implicit trust (not just MCP tool descriptions —
  RAG-retrieved documents, email/ticket content in an agent's inbox
  workflow) is a candidate for the same underlying attack pattern; see
  `ai-security/prompt-injection.md` for the general indirect-injection
  case this specializes.
- Re-audit MCP servers that were approved long ago and have since shipped
  updates — a rug-pull is specifically designed to be invisible to a
  one-time-approval mental model.

## Related CVEs
- CVE-2025-54136 (CVSS 8.8) — Cursor IDE failed to re-validate tool
  definitions after user approval, letting an attacker replace an
  approved benign configuration with a malicious payload that executed
  silently on subsequent launches — a rug-pull-class real-world CVE.
- CVE-2025-6514 (CVSS 9.6) — `mcp-remote` passed attacker-controlled
  URLs directly to a system shell (RCE, not pure prompt-level poisoning,
  but frequently cited alongside tool-poisoning research and covered in
  `ai-security/mcp-supply-chain-attacks.md`).

## Related Bug Bounty Reports
- (MCP/agent-specific bug bounty disclosures are still sparse as of
  2026 — add specific disclosed reports here as they surface.)

## Related Research
- Cloud Security Alliance — "MCP Tool Poisoning: Adversarial Hijacking of
  AI Agent Workflows" research note.
- MCPTox (arXiv 2508.14925) — benchmark, 45 live MCP servers / 353 tools,
  attack success rates 60-72.8% across current agents.
- Parasites in the Toolchain (arXiv 2509.06572) — large-scale analysis of
  attacks across the MCP ecosystem.
- OWASP MCP Top 10 — MCP03:2025 (Tool Poisoning).

## Practical Hunting Tips
- When assessing an agent deployment, don't just review the *current*
  tool descriptions — check whether the client re-validates definitions
  every session or only at first approval; the rug-pull class is
  invisible to a point-in-time manifest review.
- Test tool-returned *content*, not just static descriptions, for
  injection — an agent that trusts tool output equally to tool metadata
  is vulnerable even if every registered tool's description is clean.

## Real World Examples
- Invariant Labs PoC (April 2025) — exfiltrated private GitHub repos and
  WhatsApp message history via poisoned tool descriptions that appeared
  benign in review interfaces.
- CVE-2025-54136 — Cursor IDE rug-pull RCE.
- postmark-mcp (2026) — see `ai-security/mcp-supply-chain-attacks.md`
  for the supply-chain angle on the same incident.

## References
- https://labs.cloudsecurityalliance.org/research/csa-research-note-mcp-tool-poisoning-ai-agent-exfiltration-2/
- https://arxiv.org/pdf/2508.14925
- https://arxiv.org/pdf/2509.06572
- https://owasp.org/www-community/attacks/MCP_Tool_Poisoning

---
*Added 2026-09-04 via research pass.*
