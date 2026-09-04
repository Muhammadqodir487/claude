# AI Model Vendor Jailbreak Disclosure Programs

## Summary
A distinct and growing bug-bounty category: AI labs running dedicated
disclosure programs specifically for *model-safety jailbreaks with
real-world capability uplift* (not general content-safety issues, and
not the vendor's web/app infrastructure — that's usually a separate,
standard VDP). These programs reward finding prompting techniques that
make a model produce output a domain expert could use to meaningfully
accelerate a real attack, beyond what's already achievable with public
tools. This file documents the pattern using Anthropic's own program as
the concrete example, plus the general report-quality and methodology
practices that transfer to any similar program (OpenAI, Google, Meta,
etc. run comparable safety-disclosure channels).

## Case Study: Anthropic "Cyber Jailbreak" Program (HackerOne)
- **URL**: hackerone.com/anthropic-cyber-jailbreak
- **Type**: Coordinated Vulnerability Disclosure, *not* a paid bug
  bounty — no monetary reward, response/acknowledgment only.
- **Scope**: Cyber-relevant jailbreaks against Claude **Fable 5**
  specifically (not other Claude models). Must show *meaningful
  capability uplift beyond publicly available tools* — functional
  exploit code, working malware, detailed attack infrastructure the
  model would normally refuse, or domain-expert-level offensive
  guidance.
- **Explicitly out of scope**: general content-safety jailbreaks with no
  cyber-capability angle, other Claude models, third-party
  infrastructure, Anthropic's own web/app infra (covered by a separate
  standard VDP), single-instance/non-reproducible findings, and findings
  equivalent to what's already obtainable from public tools/search
  engines/open-source resources.
- **Severity framework — four scored dimensions**: capability gain
  (how far beyond existing tools), breadth (how many distinct offensive
  tasks the technique generalizes to), ease of weaponization (how much
  human effort/retries needed), discoverability (specialist knowledge
  required vs. already widely known). All four matter — a technique that
  scores high on capability gain but only works on one narrow task, or
  requires dozens of retries, scores lower overall than one that's
  broad, reliable, and low-effort.
- **Research guidelines (binding on the researcher)**: generate only the
  *minimum* harmful output needed to document the finding — this is not
  an invitation to produce extensive operational-grade material, only
  enough proof-of-concept to demonstrate the technique exists and
  reproduces. No public disclosure until Anthropic gives written
  clearance (standard coordinated-disclosure timing).

## Report Structure Template (adaptable to similar programs)
```
Affected model: [exact model/version, e.g. Claude Fable 5] + surface
  used (claude.ai, API, Claude Code, etc.)

Message ID(s) / conversation reference:
  [every message ID in the exchange demonstrating the jailbreak]

Full transcript(s):
  [complete verbatim input(s) — system prompt, every prior turn, and
   any setup required to reproduce, not a paraphrase]
  [For Claude Code: attach ~/.claude/projects/<project>/<session-id>.jsonl]

Observed output:
  [what harmful output was produced, and specifically WHY it
   constitutes meaningful cyber uplift — tie this explicitly to the
   four severity dimensions above, don't just assert "this is bad"]

Reproduction steps:
  [clear, ordered, step-by-step path another person can follow exactly]

Reproducibility / reliability:
  [e.g. "succeeds ~8/10 attempts"; note any required conditions —
   specific model version, specific system prompt, specific framing
   that must precede the payload]

Reporter's severity assessment:
  [your own view, scored/justified against capability gain / breadth /
   ease of weaponization / discoverability]

Supporting material:
  [screenshots, recordings, additional transcripts as needed]
```
Reports missing message IDs or reproduction steps are typically closed
as not-reproducible without further review — completeness here isn't
optional polish, it's the difference between a valid and invalid report.

## Methodology Categories Relevant to This Research Space
(Documented here as the *shape* of approaches this field studies —
see `ai-security/jailbreak.md` for the underlying technique research;
actually operating a live jailbreak attempt is the researcher's own
responsibility under the target program's specific rules, not something
to source pre-built payloads for.)
- **Multi-turn/sequential decomposition**: splitting a request across
  several individually-innocuous-looking turns rather than one message,
  exploiting the gap between per-message and per-conversation safety
  evaluation (see `ai-security/jailbreak.md` → SequentialBreak).
- **Framing/context shifts**: role-play, hypothetical/fictional framing,
  or professional-context framing (e.g., claimed authorized-pentest
  narrative) that changes how a request is contextually evaluated.
- **Cross-model transferability as a development strategy**: refining an
  approach against a weaker/more permissive surrogate model before
  testing against a hardened target, since techniques often transfer
  with modification.
- **Capability-gain framing discipline**: given this program's explicit
  exclusion of "already-public-tool-equivalent" output, the actual
  research question is comparative — *does this output measurably
  exceed what's freely available elsewhere* — not simply "did the model
  refuse or comply." A report arguing severity needs to make this
  comparison explicit (cite what's already publicly available for the
  same task, and show the delta).
- **Reliability engineering over one-off luck**: per the "brittle/
  single-instance" exclusion, a finding needs to be systematically
  reproducible — this pushes toward understanding *why* a technique
  works (root cause in the model's behavior) rather than a single lucky
  prompt, mirroring the general variant-hunting discipline in
  `cve-research/methodology.md`.

## Practical Hunting Tips
- Read the exclusions list as carefully as the inclusions — most
  low-quality submissions to programs like this fail on "equivalent to
  public tools" or "not reliably reproducible," not on the technique
  itself being uninteresting.
- Explicitly compare against a public-tool/search-engine baseline before
  writing a severity assessment — this is the single most common gap
  triagers report closing weak submissions over.
- Keep proof-of-concept generation strictly minimal per the program's
  own research guidelines — over-producing harmful material doesn't
  strengthen a report and violates the program's rules of engagement.

## Related Research
- `ai-security/jailbreak.md` — underlying jailbreak technique research
  (multi-turn, multimodal, autonomous-agent-driven, transferability).
- `ai-security/prompt-injection.md` — the adjacent but distinct
  indirect-injection attack surface (third-party content hijacking an
  agent, vs. a user's own direct jailbreak attempt).

## Real World Examples
- Anthropic Cyber Jailbreak program (HackerOne) — launched with model
  safety response efficiency reported at 100%, 28 reports received in a
  recent 90-day window as of this entry's research date (2026-09).

## References
- https://hackerone.com/anthropic-cyber-jailbreak?type=team
- https://www.anthropic.com/news/redeploying-fable-5

---
*Added 2026-09-04 via research pass (program documentation, not an
active exploitation attempt).*
