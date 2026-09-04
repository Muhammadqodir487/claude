# Security Research Knowledge Base — Index

Started: 2026-09-03. Living document — expanded incrementally (manually and via scheduled research passes).

## Structure
- `bug-bounty/` — recon methodology, chaining patterns, writeup-derived techniques, reporting strategy
- `web-security/` — deep-dives per vulnerability class (root cause → exploitation → bypass → automation → detection → mitigation)
- `ai-security/` — prompt injection, jailbreaks, agent/MCP attacks, LLM supply chain
- `cve-research/` — patch-diffing, variant hunting, exploit-dev methodology, notable CVE case studies

## Topic template (used for every web-security / cve-research file)
Summary, Root Cause, Attack Flow, Exploitation, Bypass, Automation, Detection,
Mitigation, Variant Hunting, Related CVEs, Related Bug Bounty Reports,
Related Research, Practical Hunting Tips, Real World Examples, References

## Files so far
- bug-bounty/methodology.md — recon → triage → chaining → reporting loop
- web-security/ssrf.md
- web-security/jwt-oauth.md
- web-security/http-request-smuggling.md — CL.TE/TE.CL, chunk-extension
  and HTTP/2-downgrade desync variants (2026)
- web-security/prototype-pollution.md — denylist-bypass patterns,
  CVE-2026-27212 (Swiper) case study
- ai-security/prompt-injection.md
- ai-security/mcp-supply-chain-attacks.md — malicious packages/servers
  (code-level compromise)
- ai-security/mcp-tool-poisoning.md — description-level indirect prompt
  injection (reasoning-level compromise); see OWASP MCP03:2025
- ai-security/jailbreak.md — multi-turn/multimodal/autonomous-agent
  jailbreak research, transferability
- web-security/graphql.md — batching/aliasing auth bypass, subscription/
  WebSocket transport gaps (CVE-2026-32594)
- web-security/ssti.md — engine fingerprinting → object-graph walk → RCE,
  denylist-bypass techniques
- bug-bounty/ai-model-vendor-jailbreak-programs.md — AI-lab jailbreak
  disclosure programs as a bug-bounty category (Anthropic Cyber
  Jailbreak / Claude Fable 5 case study), report template, severity
  framework
- cve-research/methodology.md

## Knowledge graph (cross-links between topics)
- Prototype Pollution → XSS / RCE (Node.js template engines)
- SSRF → Cloud metadata endpoints (AWS 169.254.169.254, GCP metadata, Azure IMDS) → credential theft
- Cache Poisoning / Deception → Account Takeover, stored XSS at scale
- JWT weaknesses → OAuth flow abuse (confused deputy, redirect_uri manipulation)
- CSP misconfiguration → XSS bypass (JSONP endpoints, unsafe-inline exceptions, allowlisted CDNs with user uploads)
- Deserialization (Java/PHP/.NET) → RCE via gadget chains
- IDOR → often chained with predictable-ID enumeration + missing rate limiting
- Prompt Injection (indirect, via RAG/tool output) → Agent tool-calling abuse → data exfiltration or unauthorized actions
- Race Conditions → business logic bypass (double-spend, coupon reuse, limit bypass)
- HTTP Request Smuggling → WAF/auth bypass, cache poisoning, cross-user response/request leakage
- Prototype Pollution → Auth bypass / DoS in addition to XSS/RCE (CVE-2026-27212 pattern: denylist-bypass reintroduces the bug after a prior fix)
- MCP Tool Poisoning (description-level) → same exfiltration/unauthorized-action impact as classic indirect Prompt Injection, but via tool metadata/response content instead of RAG/document content
- MCP rug-pull (definition changes post-approval) → persistent covert agent access, distinct from one-time supply-chain compromise
- SonicWall SMA1000 SSRF + OS command injection (CVE-2026-83548/83549) → chained appliance compromise, same vendor/product line
- GraphQL subscription/WebSocket transport → same auth-bypass root cause as MCP transport-specific gaps (middleware wired into one transport, not re-verified on another)
- SSTI → RCE (near-immediate, unlike most injection classes) via template-engine object-graph traversal (Python __mro__, Java reflection)
- LLM Jailbreak (direct, user-driven) → distinct from indirect Prompt Injection, but chains with it when injected third-party content itself carries a jailbreak payload
- AI-lab jailbreak disclosure programs (bug-bounty/ai-model-vendor-jailbreak-programs.md) → require demonstrating capability uplift beyond public tools, not just successful refusal bypass

## Update log
- 2026-09-03: Initial scaffold + 5 seed documents created.
- 2026-09-03: Added ai-security/mcp-supply-chain-attacks.md (postmark-mcp
  malicious MCP server, CVE-2025-6514 core-MCP RCE, LiteLLM PyPI
  backdoor). Appended 4 real-world CVE entries to
  cve-research/methodology.md (CVE-2026-50522 SharePoint, CVE-2026-81934
  Redis, CVE-2026-62911 Exchange, Aug 2026 Patch Tuesday scale context).
- 2026-09-04: Added web-security/http-request-smuggling.md (CL.TE/TE.CL,
  2026 malformed chunk-extension technique, HTTP/2 downgrade desync,
  CVE-2026-48710) and web-security/prototype-pollution.md
  (CVE-2026-27212 Swiper denylist-bypass case study, child_process RCE
  gadget). Added ai-security/mcp-tool-poisoning.md as a companion to
  mcp-supply-chain-attacks.md, covering description-level indirect
  prompt injection, rug-pulls, tool shadowing (OWASP MCP03:2025,
  MCPTox benchmark, CVE-2025-54136). Appended Sept 2026 CISA KEV batch
  (9 CVEs across Sangoma, Starlette, Kestra, LiteLLM, Artifactory,
  SonicWall, PaperCut) to cve-research/methodology.md. Note: the "daily
  scheduled routine" referenced in this KB's own memory pointer was
  found NOT to actually exist (no cron job present) — recreate it if
  continuous unattended updates are wanted; otherwise this KB grows via
  on-demand research passes like this one.
- 2026-09-04 (session 2): KB converted to a git repo, pushed to
  https://github.com/Muhammadqodir487/claude. Attempted to set up a real
  daily cloud routine (RemoteTrigger/`schedule` skill) — blocked by a
  claude.ai/code/routines UI bug ("Select a repository" unresponsive);
  filed as feedback, not yet resolved. Added web-security/graphql.md
  (CVE-2026-32594 Parse Server WebSocket auth bypass, neo4j/graphql
  subscription JWT bypass, Shopify BOLA bounty), web-security/ssti.md
  (Jinja2/FreeMarker RCE chains, pipe-filter/hex-encoding bypasses),
  ai-security/jailbreak.md (2026 Nature Communications autonomous
  AI-to-AI jailbreak study, JBFuzz, SequentialBreak, multimodal
  jailbreaks), and bug-bounty/ai-model-vendor-jailbreak-programs.md
  (documents Anthropic's Cyber Jailbreak/Fable-5 HackerOne program as a
  new bug-bounty category, with report template and severity framework
  — documentation only, no live jailbreak attempts were made against
  any Claude model per this KB's own scope).
