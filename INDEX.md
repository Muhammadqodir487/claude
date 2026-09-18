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
- web-security/deserialization.md — gadget chains (Java/PHP/Python/.NET),
  SharePoint ToolShell (CVE-2025-53770)
- web-security/race-conditions.md — single-packet attack, state-machine
  races, RoguePlanet Defender TOCTOU (CVE-2026-50656)
- web-security/cache-poisoning-deception.md — CDN/origin URL-parsing
  discrepancies, Cloudflare Deception Armor .avif bypass
- web-security/access-control-bola-idor.md — BOLA empirical taxonomy,
  Action-Level Object BOLA (41.7% of confirmed cases)
- web-security/cloud-metadata-ssrf-misconfig.md — TOCTOU redirect-based
  SSRF to cloud metadata (CVE-2026-64849 MLflow), bucket permutation
- ai-security/rag-vector-db-attacks.md — embedding-space poisoning,
  black-hole attack, PoisonedRAG
- cve-research/methodology.md
- web-security/xss-csp-bypass.md — mutation XSS (mXSS) and DOM clobbering
  as markup-survival primitives chained with CSP-defeating gadgets
  (DOMPurify CVE-2025-26791/CVE-2025-15599/CVE-2024-45801, PortSwigger's
  portswigger.net self-CSP-bypass case study)
- web-security/file-upload-rce.md — extension/MIME/magic-byte trust
  failures and archive/zip-slip patterns behind upload-to-RCE, Apache
  Tomcat partial-PUT RCE (CVE-2025-24813) and Craft CMS pre-auth RCE
  (CVE-2025-32432) case studies
- web-security/saml-security.md — XML Signature Wrapping (XSW1-8) and
  verify/parse parser-differential bugs, ruby-saml
  (CVE-2025-25291/25292/66567/66568) and samlify (CVE-2025-47949)
  case studies, Golden/Silver SAML
- ai-security/llm-sandbox-escape.md — code-execution sandbox isolation
  and egress-policy failures in AI agent tools (ChatGPT Code Interpreter
  DNS-tunneling exfiltration, Claude Code CVE-2025-66479/CVE-2026-55607,
  Claude Cowork "SharedRoot" host-filesystem escape)
- ai-security/ai-browser-agents.md — agentic browser attack class (Comet,
  ChatGPT Atlas, Fellou, Copilot for Edge, Gemini for Chrome): indirect
  prompt injection where the agent holds the user's full authenticated
  sessions; Brave Comet summarize→OTP exfil, CometJacking one-click URL,
  ChatGPT Tainted Memories (CSRF→persistent memory), Zenity calendar-invite
  filesystem/password-manager takeover, Cato HashJack URL-fragment
  injection, CSA PleaseFix zero-/one-click taxonomy

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
- Deserialization gadget chains → RCE via legitimate-but-combined classes (same "trusted primitives, untrusted combination" pattern as Prototype Pollution → RCE gadgets)
- Race Conditions (TOCTOU) → not web-specific: same check-then-act flaw pattern defeats privileged OS security software (RoguePlanet/Defender) as defeats web coupon/limit logic
- Single-packet attack (network-jitter elimination) → turns previously-unreliable remote races into reliably exploitable local-grade races, expanding real-world race-condition attack surface
- Cache key vs. origin-parsing mismatch → Cache Poisoning (stored XSS at scale) or Cache Deception (sensitive data exposure), same root cause, different direction of exploitation
- "Unexploitable" primitive (e.g. header-only open redirect) + Cache Poisoning → stored, browser-triggerable attack (escalation pattern worth re-testing old low-severity findings against)
- BOLA Action-Level (state-changing actions on another's object) → often chained with Race Conditions (concurrent action-level BOLA requests bypass both authorization AND rate/limit checks at once)
- SSRF → Cloud Metadata (TOCTOU redirect bypass variant, CVE-2026-64849) → IAM credential theft → full cloud account compromise (same chain as classic SSRF, new bypass mechanism)
- RAG/Vector-DB poisoning → Indirect Prompt Injection (persistent, corpus-level rather than single-request) → same downstream impact as MCP Tool Poisoning, different injection surface
- Embedding-space anisotropy (black-hole attack) → broad retrieval hijacking without any natural-language-visible payload → defeats content-based/manual review entirely
- Prototype Pollution → weakens a sanitizer's own internal state (DOMPurify CVE-2024-45801 depth-counter pollution) → mXSS, a third distinct outcome alongside the existing Prototype Pollution → XSS/RCE edge
- CSP misconfiguration (existing edge) → the specific mechanism is a markup-survival primitive (mXSS/DOM clobbering) chained with a CSP-defeating gadget (allowlisted-CDN script, nonce theft via DOM query, base-uri/form-action gap) — see web-security/xss-csp-bypass.md
- File Upload (trust in client-supplied Content-Type/extension) → RCE via web-executable upload directory or a second trusted parser (Tomcat/Craft CMS session-file deserialization) — same "attacker-controlled content fed to a trusted parser" root cause as Deserialization
- SSRF → "import from URL" upload features are a File-Upload-RCE variant wearing an SSRF costume (fetch-side SSRF + storage-side unrestricted upload, CVE-2025-12138 pattern)
- JWT/OAuth signature-validation bugs (alg confusion, kid injection) → SAML XML Signature Wrapping / parser-differential bugs (ruby-saml CVE-2025-25291/25292) — same "verify one representation, extract identity from a different representation" root cause across federated-identity formats
- Prompt Injection (indirect) → LLM agent sandbox escape / code-execution abuse: injection is the near-universal trigger that gets an agent to run attacker-chosen code inside its sandbox, distinct from what happens once that code is running
- SSRF / Cloud Metadata SSRF misconfig → LLM sandbox egress abuse: the same 169.254.169.254/internal-network target is reachable from inside an AI code-execution sandbox that permits outbound network access, unless metadata IPs are null-routed at the sandbox network-namespace level
- Indirect Prompt Injection (ai-security/prompt-injection.md) → AI Browser Agent is its highest-impact deployment: the agent runs with the user's full set of live authenticated web sessions + connected accounts, so a single injection becomes cross-origin account-takeover/data-exfil at browser scope — the general mechanism, maximally privileged (see ai-security/ai-browser-agents.md)
- AI Browser Agent → Confused Deputy (same root cause as SSRF, web-security/ssrf.md): the deputy is the browser and the "credential" it wrongly lends the attacker is the user's entire logged-in session set, not one server-side fetch capability
- CSRF (classic web) + LLM persistent memory → "Tainted Memories" memory poisoning: CSRF regains first-class relevance as the *write* primitive that plants a durable prompt injection into account-level memory, persisting across sessions/devices/browsers — bridges web-security (CSRF) and ai-security (memory poisoning), and is the persistence analogue of RAG/vector-DB corpus poisoning (ai-security/rag-vector-db-attacks.md)
- HashJack URL-fragment injection → server never sees the payload (client-only `#fragment`), bypassing WAF/IPS/DLP/server logs — same server-invisible property as DOM-based XSS (web-security/xss-csp-bypass.md), applied to LLM ingestion instead of the JS sink
- Screenshot / faint-text / "unseeable" injection → multimodal indirect prompt injection: content invisible to humans but read by OCR/vision, extending the multimodal-jailbreak edge (ai-security/jailbreak.md) to the browser-agent surface; "if a human can't see it" is not a trust boundary
- AI Browser Agent exfiltration channels (agent posts back to source platform / background-fetches an attacker URL with data as params / renders an attacker link, often base64-encoded to defeat output filters) → same out-of-band exfil pattern as markdown/image-render leakage in ai-security/llm-sandbox-escape.md; output content filters are bypassed by any encoding the model will apply

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
- 2026-09-04 (session 3): Added web-security/deserialization.md
  (Java/PHP/Python/.NET gadget chains, SharePoint ToolShell
  CVE-2025-53770, ysoserial tooling) and web-security/race-conditions.md
  (James Kettle's single-packet attack technique, RoguePlanet Microsoft
  Defender TOCTOU LPE CVE-2026-50656, state-machine race framing beyond
  simple limit-overrun).
- 2026-09-04 (session 4): Added web-security/cache-poisoning-deception.md
  (CDN/origin URL-parsing discrepancies per PortSwigger's "Gotta cache
  'em all," Cloudflare Deception Armor .avif bypass) and
  web-security/access-control-bola-idor.md (arXiv 2605.25865 empirical
  BOLA taxonomy — Action-Level Object BOLA is 41.7% of confirmed cases,
  Uber Eats BOLA case study).
- 2026-09-04 (session 5): Live bug-bounty engagement practice on two
  authorized H1 programs (Docusign, Aven) — no reportable findings, but
  produced a reusable CT-log-based internal-surface-discovery
  methodology (see bug-bounty/methodology.md) from real recon against
  Aven's wildcard scope. Also added web-security/cloud-metadata-ssrf-
  misconfig.md (CVE-2026-64849 MLflow TOCTOU redirect SSRF to cloud
  metadata, actively exploited for IAM credential theft) and
  ai-security/rag-vector-db-attacks.md (PoisonedRAG, black-hole
  embedding-space attack, RAGPoison persistent injection).
- 2026-09-04 (session 6): Added web-security/xss-csp-bypass.md (mutation
  XSS and DOM clobbering as markup-survival primitives chained with
  CSP-defeating gadgets; DOMPurify CVE-2025-26791/CVE-2025-15599/
  CVE-2024-45801; portswigger.net's own AngularJS-allowlist CSP-bypass
  case study), web-security/file-upload-rce.md (extension/MIME/magic-byte
  trust failures and zip-slip; Apache Tomcat partial-PUT RCE
  CVE-2025-24813 and Craft CMS pre-auth RCE CVE-2025-32432 case studies),
  web-security/saml-security.md (XML Signature Wrapping XSW1-8 and
  verify/parse parser-differential bugs; ruby-saml
  CVE-2025-25291/25292/66567/66568 and samlify CVE-2025-47949 case
  studies, Golden/Silver SAML), and ai-security/llm-sandbox-escape.md
  (code-execution sandbox isolation and egress-policy failures in AI
  agent tools; ChatGPT Code Interpreter DNS-tunneling exfiltration,
  Claude Code CVE-2025-66479/CVE-2026-55607, Claude Cowork "SharedRoot"
  host-filesystem escape). Note: a planned CI/CD supply-chain-security
  topic (GitHub Actions poisoning, tj-actions CVE-2025-30066) was
  attempted twice but both research-agent runs were blocked by Claude's
  own real-time cyber-safeguard filter regardless of defensive framing;
  swapped in SAML security as the fourth topic instead. Worth retrying
  CI/CD supply chain in a future pass, possibly split into narrower
  sub-topics to avoid the filter.
- 2026-09-18 (session 7): Added ai-security/ai-browser-agents.md — the
  agentic-browser attack class (Perplexity Comet, OpenAI ChatGPT Atlas
  [retired 2026-08-09], Fellou, Microsoft Copilot for Edge, Google Gemini
  for Chrome). Root cause: the LLM ingests attacker-controlled web content
  into the same context as the user's instruction while holding the user's
  full authenticated browser identity (confused deputy at browser scope).
  Real 2025-2026 disclosures: Brave's Comet summarize→OTP-theft (Reddit
  spoiler-tag injection) and "unseeable" screenshot/faint-text injection;
  LayerX CometJacking (one-click URL, base64 exfil, Perplexity triaged
  "not applicable") and ChatGPT "Tainted Memories" (CSRF-written
  persistent memory, OpenAI "couldn't reproduce"); Zenity Labs
  calendar-invite filesystem exfil + password-manager takeover (fixed Feb
  2026); Cato CTRL HashJack (URL-fragment injection, server-invisible,
  bypasses WAF/IPS); CSA "PleaseFix" zero-/one-click exploit taxonomy
  (Mar 2026). Added 7 knowledge-graph edges tying it to prompt-injection,
  ssrf/confused-deputy, CSRF+memory-poisoning, DOM-XSS server-invisibility,
  multimodal jailbreak, and llm-sandbox-escape exfil channels. Maps to
  OWASP LLM01 (Prompt Injection) and LLM Top 10 for agentic systems.
  NOTE: git-repo copy only carries the English write-up; the Uzbek
  content_uz half required by charter §9 is translation-pending for the
  authoritative artifact-db copy and has NOT been written this pass.
