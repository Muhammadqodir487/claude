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

The primary, cross-session copy of this KB lives in a published Claude
Artifact's shared database (see the Claude memory pointer for the URL) —
not this git repo. A scheduled cloud routine (claude.ai/code/routines) runs
daily: reads `meta/charter` + `meta/index` + all `topics` docs from that
artifact db, picks 1-3 uncovered or stale topics (checking off the Scope
list above and the Sources list for anything new), does a real research
pass (WebSearch/WebFetch), writes new `topics` docs per the template in
section 5, and updates `meta/index` (file list + knowledge graph + update
log). This git repo (`~/security-research-kb/`, pushed to GitHub) is a
secondary/legacy copy kept in sync manually — it does not update itself,
so don't assume it's current; treat the artifact db as authoritative. If
the routine is ever found not to be firing, treat that as a bug to fix, not
a reason to lower scope — this charter's scope stands regardless of which
mechanism (manual session or scheduled routine) is currently executing it.

## 7. Emerging incident tracking

Beyond the deep-dive topic files (section 5's 15-section template, meant
for stable, well-established techniques), the KB also keeps a lightweight,
frequently-updated **incident feed** for newly disclosed vulnerabilities
and active/ongoing cyberattacks — the "what just happened" layer, distinct
from the "how the technique works" layer. Each incident entry is short:
date, title, one-paragraph summary, CVE id(s) if any, real source URL(s),
and (optionally) which existing topic file it relates to or extends. A
routine or manual pass should add an incident entry whenever it finds a
genuinely new, real, dated disclosure (a fresh CVE, an active KEV addition,
a breaking bug-bounty writeup, a live attack campaign) — even one not yet
worth a full topic file. When an incident matures into a well-documented
pattern worth deep methodology extraction, promote it into a real
section-5 topic file (and note the promotion in the incident entry and the
update log) rather than duplicating the content in both places.

## 8. OWASP alignment

The KB explicitly tracks and maps its coverage against the standing OWASP
Top-10-style catalogs relevant to its scope:
- **OWASP Top 10 (Web Application Security)** — A01 Broken Access Control
  through A10 Server-Side Request Forgery.
- **OWASP API Security Top 10** — API1 Broken Object Level Authorization
  through API10.
- **OWASP Top 10 for LLM Applications** — LLM01 Prompt Injection through
  LLM10, covering the ai-security scope.
- **OWASP MCP Top 10 / MCP security guidance** (e.g. MCP03:2025 tool
  poisoning, already referenced in `ai-security/mcp-tool-poisoning.md`) —
  covering MCP-specific agent/tool-security scope.

A mapping of KB topics to these catalog codes is maintained as structured
data alongside `meta/index` (not duplicated as prose in every topic file).
When a new topic is added, map it to the relevant catalog code(s) it
falls under; when a pass has spare capacity, check the mapping for a
catalog code with no mapped topic yet and treat that as a real scope gap
to prioritize — the OWASP catalogs are a coverage checklist, not just a
citation source.

## 9. Bilingual documentation (English + Uzbek)

The user reads the KB in both English and Uzbek. Every document that
carries prose content keeps a parallel Uzbek translation alongside the
English original, in the same record rather than a separate file/doc:
- `meta/charter` — `content` (English, authoritative for wording changes)
  plus `content_uz` (full Uzbek translation, kept in sync).
- `meta/index` — `content` plus `content_uz`.
- `topics` collection — `title`/`content` (English) plus `title_uz`/
  `content_uz` (Uzbek). Translate the full 15-section write-up, not a
  summary — technical terms, CVE IDs, code, and URLs stay as-is (untranslated) inside the
  translated prose; only the surrounding natural-language explanation is
  translated.
- `incidents` collection — `title`/`summary` plus `title_uz`/`summary_uz`.

English is authoritative: when editing existing content, update the
English first, then update the matching Uzbek translation in the same
write (or, if that's not practical in one pass, flag it — e.g. via the
update log — as translation-pending rather than letting it silently
drift out of sync). A new topic/incident is not "done" until both
language fields are populated; a pass that only writes the English half
should say so explicitly in its final report rather than reporting the
work as complete. Official framework/standard terminology (OWASP catalog
codes and titles, CVE IDs, protocol/spec names) is not translated — it
stays as the industry uses it in both language versions. The `meta/
owasp_map` structured JSON is reference data, not prose, and is not
translated.
