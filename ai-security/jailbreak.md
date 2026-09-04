# LLM Jailbreaking

## Summary
Jailbreaking is getting a model to violate its own safety
policy/training through the input alone — distinct from prompt
injection (see `ai-security/prompt-injection.md`), which hijacks an
*agent's* behavior via untrusted third-party content rather than the
end user's own direct prompt. The two are frequently chained in
practice (an indirect-injection payload can itself contain a jailbreak
payload aimed at getting the agent's underlying model to ignore its
instructions once the injected content reaches its context) but are
different attack surfaces with different defenses. By 2026 the field has
moved decisively from hand-crafted one-off prompts to fully automated,
even autonomous-AI-driven, jailbreak generation at scale.

## Root Cause
- Safety alignment is trained behavior, not an architectural boundary —
  there is no hard wall between "the model's reasoning" and "the model's
  safety judgment"; both are the same weights, so any input that shifts
  the model's contextual framing enough can shift which behavior that
  training expresses.
- Multi-turn/sequential framing dilutes the single-turn safety signal a
  model was most heavily trained against — splitting a harmful request
  across a chain of individually-innocuous-looking prompts exploits the
  gap between "does this single message look harmful" and "does this
  multi-turn trajectory add up to a harmful outcome."
- Cross-modal safety training lags text-only safety training — safety
  tuning applied primarily to text inputs doesn't automatically transfer
  to audio/image inputs carrying semantically equivalent harmful content,
  leaving multimodal models measurably more exploitable via non-text
  channels.
- Transferability: because many current-generation models are trained
  with broadly similar techniques/data and converge on similar
  representations, a jailbreak crafted against one model frequently
  works with only minor modification against a completely different
  model/vendor — the underlying vulnerability is not fully
  model-specific.

## Attack Flow
1. Select a framing strategy: role-play/persona override, hypothetical/
   fictional framing, multi-turn incremental escalation
   ("SequentialBreak"-style chains), or an automated search/fuzzing
   process rather than a single hand-written prompt.
2. For automated approaches, run a fuzzing or optimization loop against
   the target model (or a surrogate) scoring each candidate prompt by
   whether it elicits the target harmful behavior, iterating toward
   higher success-rate variants.
3. For autonomous-agent approaches (2026 state of the art), give a
   *second* LLM the standing instruction "break this other model" with
   no further human guidance, and let it plan and execute a multi-turn
   jailbreak strategy against the target model on its own, adapting
   based on the target's responses turn by turn.
4. Once a working jailbreak is found against one target, test it against
   other models with minor rephrasing — transferability means the
   marginal cost of a second/third successful jailbreak from a working
   first one is often low.

## Exploitation
- **Autonomous AI-to-AI jailbreaking (Hagendorff et al., Nature
  Communications, 2026)**: large reasoning models (DeepSeek-R1,
  Gemini 2.5 Flash tested as attackers) given only the instruction to
  break other models, with no human in the loop, independently planned
  and executed multi-turn jailbreak strategies — 97.14% overall success
  rate across attacker-target model pairings tested. Notable finding:
  Claude 4 Sonnet was the strongest holdout among targets, refusing
  roughly half the time and producing the lowest harm scores of the
  models tested.
- **JBFuzz (fuzzing-based, 2025-2026)**: a coverage/feedback-guided
  fuzzing framework for jailbreak prompt discovery, achieving roughly
  99% average attack success rate across GPT-4o, Gemini 2.0, and
  DeepSeek-V3 — illustrates that even without an autonomous-agent
  attacker, automated search alone is now extremely effective against
  current safety training.
- **SequentialBreak (arXiv 2411.06426)**: embeds a jailbreak payload
  across a sequential chain of prompts rather than one message, exploiting
  the gap between per-turn and per-conversation safety evaluation.
- **Multimodal jailbreaks**: audio inputs with adversarially engineered
  pitch/background-noise compositional changes achieved over 70% success
  against Gemini Pro and GPT-4o Realtime — a channel most text-focused
  safety evaluation doesn't cover with equivalent rigor.
- **Symbolic-mathematics encoding (arXiv 2409.11445)**: encoding a
  harmful request as a symbolic-math problem the model is asked to
  "solve," exploiting the model's willingness to engage with abstract
  formal-notation framing that doesn't pattern-match to the model's
  harmful-content training examples.

## Bypass
- Cross-model transferability itself functions as a bypass technique
  against any single model's specific defenses: a prompt refined against
  a weaker or open-weight model as a surrogate frequently transfers with
  minor edits to a stronger, more heavily-defended target — attackers
  don't need query access to a hardened target to develop an effective
  payload against it.
- Multi-turn/sequential decomposition bypasses defenses tuned to
  evaluate single-turn harmfulness, by construction — this is a
  structural bypass of any purely-per-message safety classifier, not a
  clever wording trick.

## Automation
- JBFuzz and comparable fuzzing frameworks industrialize jailbreak
  discovery: candidate generation, target querying, and success scoring
  run as an automated loop rather than manual prompt iteration.
- The Nature Communications 2026 result effectively demonstrates full
  end-to-end automation of *both* strategy generation and execution via
  a second LLM as the attacker — the human's role reduces to giving the
  initial standing instruction.

## Detection
- Multi-turn conversation-level classifiers (evaluating trajectory, not
  just the latest message) are necessary to catch sequential/incremental
  jailbreaks that no single message in the chain would flag on its own.
- Cross-modal content moderation (analyzing audio/image inputs for
  semantic content equivalent to blocked text, not just running
  text-only classifiers on a transcript) is needed given the
  demonstrated multimodal-jailbreak success rates above.
- Anomalous multi-turn escalation *patterns* (steadily narrowing toward
  a specific harmful topic across many turns) are a detectable behavioral
  signal independent of any single message's content.

## Mitigation
- Defense-in-depth beyond model-level alignment: output-side content
  filtering/classification as a second independent layer, since
  input-side jailbreak resistance alone has repeatedly proven
  incomplete against automated/adversarial search at scale.
- Rate-limit and flag automated high-volume querying patterns consistent
  with fuzzing-based jailbreak discovery (JBFuzz-style) at the API level,
  independent of per-request content analysis.
- Treat cross-modal inputs as requiring their own dedicated safety
  evaluation pipeline, not a downstream transcript fed through
  text-only moderation.

## Variant Hunting
- Any newly-released model or modality (a new multimodal input type, a
  new "agentic" or tool-using mode) should be assumed under-defended
  relative to mature text-chat safety training until specifically
  tested — the multimodal-jailbreak success-rate gap shows safety
  training measurably lags capability rollout by modality.
- Given demonstrated transferability, a jailbreak found against any one
  major model is worth testing with minor rephrasing against every other
  major model as a near-zero-additional-cost check.

## Related CVEs
- (Jailbreaks are typically not tracked as CVEs — this is a model-
  behavior/alignment research area rather than a software-implementation
  vulnerability class; cross-reference `ai-security/prompt-injection.md`
  and `ai-security/mcp-tool-poisoning.md` for the adjacent
  implementation-level CVEs in agent tooling.)

## Related Bug Bounty Reports
- (Model providers increasingly run dedicated AI red-teaming/bug-bounty
  programs distinct from standard web bug bounty platforms — populate
  with specific disclosed findings as found.)

## Related Research
- Hagendorff et al., "Large reasoning models are autonomous jailbreak
  agents," Nature Communications, 2026.
- JBFuzz (2025-2026 fuzzing-based jailbreak framework).
- SequentialBreak, arXiv 2411.06426.
- "Jailbreaking Large Language Models with Symbolic Mathematics,"
  arXiv 2409.11445.
- SplX.ai — "Jailbreaking Multimodal LLMs: New Exploits Targeting
  State-of-the-Art Models."

## Practical Hunting Tips
- When red-teaming an agent/product built on an LLM, test multi-turn
  escalation specifically, not just single-message jailbreak libraries —
  per-message-only testing systematically misses the sequential-
  decomposition class, which is currently one of the most effective
  categories.
- If the product accepts audio/image input, budget dedicated testing
  time for multimodal jailbreak variants — this surface is measurably
  less mature than text and is being under-tested by teams that port
  over a text-only jailbreak test suite unchanged.

## Real World Examples
- Nature Communications 2026 autonomous-jailbreak-agent study —
  97.14% cross-model success rate, DeepSeek-R1/Gemini 2.5 Flash as
  tested attackers, Claude 4 Sonnet as the strongest tested holdout.
- JBFuzz — ~99% average success rate across GPT-4o, Gemini 2.0,
  DeepSeek-V3.

## References
- https://www.nature.com/articles/s41467-026-69010-1
- https://splx.ai/blog/jailbreaking-multimodal-llms-new-exploits-targeting-state-of-the-art-models
- https://arxiv.org/pdf/2411.06426
- https://arxiv.org/pdf/2409.11445
- https://ziosec.com/blog/ai-jailbreak-techniques-in-2026-a-complete-technical-guide-ziosec

---
*Added 2026-09-04 via research pass.*
