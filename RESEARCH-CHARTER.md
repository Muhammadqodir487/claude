# Research Charter

This file is the durable scope-and-method spec for this knowledge base. Both
manual research sessions and the scheduled research routine follow this
document. It supersedes any shorter summary elsewhere (including the Claude
memory pointer, which only records *where* this KB lives).

Never consider this KB "done." Every pass finds new material and integrates
it with what already exists — via cross-links in the knowledge graph, not by
duplicating existing files.

## 1. Scope

**Bug Bounty** — 2025-2026 writeups (HackerOne, Bugcrowd, Intigriti,
YesWeHack, Medium, Substack, GitHub, personal blogs, conference talks,
Reddit/X discussion), P1/P2 and novel attack chains, real methodology, recon
automation, vulnerability chaining.

**CVE Research** — 2025-2026 Critical/High CVEs with public PoCs/exploits,
patch-diff analysis, root cause analysis, variant hunting, exploit dev,
bypass techniques, and (for defensive/educational understanding only)
analysis of why certain mitigations fail.

**Web Security** (root cause, modern bypass, detection, automation, real
case, hunting methodology for each): SSRF, XXE, SSTI, Deserialization,
Prototype Pollution, Race Conditions, HTTP Request Smuggling, Cache
Poisoning, Cache Deception, OAuth, SAML, JWT, IDOR, Access Control, Business
Logic, GraphQL, REST API, gRPC, WebSocket, CSP Bypass, XSS, SQLi, NoSQLi,
File Upload, Request Tunneling, CORS, Clickjacking, Host Header attacks, DNS
attacks, Cloud attacks (AWS/Azure/GCP), Kubernetes, Docker, CI/CD security.

**AI Security**: Prompt Injection (direct/indirect), Jailbreak, Prompt
Stealing, Model Extraction, Data Poisoning, RAG attacks, MCP security, Tool
Poisoning, Agent attacks, Multi-agent attacks, LLM sandbox escape, Context
poisoning, Embedding attacks, Vector DB attacks, Memory poisoning, Agentic
exploitation, AI supply chain, AI browser agents, AI code agents — with
attention to vendor-specific behavior (OpenAI, Anthropic, Gemini, DeepSeek,
Qwen, Mistral, local/open-weight LLMs) where it materially changes the
attack surface.

**Offensive AI (as a research topic, not a tool to build/run here)**:
documented techniques for AI-assisted recon, fuzzing, exploit generation,
vulnerability discovery, reverse engineering, malware/static/dynamic
analysis, exploit chaining — summarized from public research, not executed
against live targets by this KB's automation.

**Sources to track**: HackerOne Hacktivity, Bugcrowd, Intigriti, YesWeHack,
Medium, GitHub, Google Project Zero, Microsoft Security Research,
PortSwigger Research, OWASP, BlackHat/DEF CON/OffensiveCon/Nullcon talks,
Reddit, X, CVE/NVD, CISA KEV, Exploit-DB, GitHub Security Advisories.

## 2. Per-source discipline

For every piece of material pulled in: cross-reference against what's
already in the KB, sanity-check credibility (primary source > aggregator),
skip near-duplicates of existing files (extend the existing file instead),
and note recency (2025-2026 preferred; older material only for root-cause
context).

## 3. Methodology extraction (not just facts)

From every writeup/article/advisory, pull out: the underlying methodology,
attack pattern, root cause, automation ideas, hunting strategy, recon
workflow, payload-generation approach, bypass technique, detection-evasion
angle (for defenders' awareness), reporting strategy, false-positive
reduction — not just "what the bug was."

## 4. Knowledge graph

`INDEX.md` maintains a running list of cross-topic causal/chaining links
(e.g. `SSRF -> AWS metadata -> credential theft`, `Prototype Pollution ->
XSS/RCE`, `JWT -> OAuth`, `Cache Poisoning -> Account Takeover`). Every new
topic file must add at least one new edge to this graph, not just a
standalone entry.

## 5. Fixed output template

Every `web-security/`, `ai-security/`, and `cve-research/` file uses:
Summary, Root Cause, Attack Flow, Exploitation, Bypass, Automation,
Detection, Mitigation, Variant Hunting, Related CVEs, Related Bug Bounty
Reports, Related Research, Practical Hunting Tips, Real World Examples,
References.

## 6. Continuous operation

A scheduled routine (see repo root / claude.ai/code/routines) runs
periodically: pulls the repo, reads this charter + `INDEX.md`, picks 1-3
uncovered or stale topics (checking off the Scope list above and the
Sources list for anything new), does a real research pass (WebSearch/
WebFetch), writes files per the template, updates `INDEX.md` (file list +
knowledge graph + update log), commits, and pushes. If the routine is ever
found not to be firing, treat that as a bug to fix, not a reason to lower
scope — this charter's scope stands regardless of which mechanism (manual
session or scheduled routine) is currently executing it.
