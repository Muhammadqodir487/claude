# RAG & Vector Database Attacks

## Summary
Retrieval-Augmented Generation (RAG) systems fetch content from a vector
database at query time and feed it into an LLM's context with the same
implicit trust as a hand-written prompt — an attacker who can influence
*what gets retrieved* controls what the model treats as ground truth,
without ever touching the model's weights, the system prompt, or the
API. OWASP's LLM Top 10 (2025) formally recognizes vector/embedding
weaknesses as a top-10 risk. This is the retrieval-side counterpart to
`ai-security/mcp-tool-poisoning.md` (tool-description-level trust abuse)
and `ai-security/prompt-injection.md` (general indirect injection) —
same underlying pattern (untrusted content inheriting trusted-context
authority), different mechanism (embedding-space manipulation rather
than natural-language instruction).

## Root Cause
- **Retrieved content is treated as trusted context** by the downstream
  LLM regardless of provenance — a RAG pipeline has no built-in notion
  of "this chunk came from an untrusted, externally-editable source,"
  so anything successfully retrieved gets the same weight as
  organization-authored source material.
- **Embedding-space anisotropy**: embeddings from real-world models
  cluster in certain directions rather than distributing uniformly
  across the vector space — this geometric defect means a carefully
  crafted vector can be positioned to score artificially high similarity
  against a broad range of queries, hijacking retrieval ranking without
  needing genuine semantic relevance to any specific query.
- **No access control at the chunk level**: many vector-store
  deployments apply document-level or corpus-level access control (if
  any) but not per-chunk provenance/trust tracking, so once a
  document is indexed, every chunk derived from it is retrievable with
  equal trust regardless of who or what supplied the source document.
- **Indirect corpus access via public-facing content**: if an attacker
  can inject content into *any* source that eventually gets crawled/
  ingested into the RAG corpus (public documentation the target scrapes,
  a vendor's own docs the target indexes, a support forum), they gain
  indirect write access to the target's retrieval index without ever
  touching the target's own infrastructure.

## Attack Flow
1. Identify what sources feed the target's RAG corpus (public docs,
   crawled web content, user-submitted content, third-party
   integrations) — the ingestion pipeline's trust boundary is the actual
   attack surface, not the LLM itself.
2. Craft content designed to be retrieved for specific target queries —
   either via natural semantic relevance (write content that legitimately
   matches expected user queries, then embed a payload within it) or via
   adversarial embedding-space crafting (optimize a vector's position to
   rank highly for target queries independent of genuine semantic
   content).
3. Get the crafted content indexed into the corpus (via whatever
   ingestion path was identified in step 1).
4. When a user's query triggers retrieval of the poisoned content, the
   embedded instructions/misinformation reach the LLM's context with
   full trust, executing an indirect-prompt-injection-style payload or
   steering the model's factual output toward attacker-chosen content.

## Exploitation
- **PoisonedRAG (USENIX Security '25)**: knowledge-corruption attacks
  demonstrating that injecting a small number of carefully crafted
  malicious texts into a knowledge database can reliably cause a RAG
  system to generate an attacker-chosen target answer for a specific
  target question — establishes the base feasibility of small-scale,
  targeted corpus poisoning.
- **Adversarial passage technique**: crafting content with embedding
  properties specifically optimized to rank highly for target queries,
  letting an attacker control which content is retrieved for a given
  topic *without relying on natural semantic matching* — meaning the
  injected content doesn't even need to read as relevant to a human
  reviewer to dominate retrieval for the targeted query.
- **Black-hole attack (arXiv 2604.05480)**: exploits embedding-space
  anisotropy directly — attacker crafts vectors aligned with directional
  concentrations in the embedding space so they artificially achieve
  high similarity scores across a *broad* range of queries (not just one
  targeted query), effectively becoming a gravitational "black hole" that
  dominates retrieval results widely. Requires only the ability to
  inject vectors into the target database and knowledge of the embedding
  model's output-space characteristics — no query-time access or model
  tampering needed.
- **RAGPoison / persistent prompt injection via poisoned vector
  databases**: once malicious content is embedded and indexed, the
  injection persists across every future query that happens to retrieve
  it — unlike a single-request prompt injection, this creates a standing
  compromise of the corpus rather than a one-shot attack.
- **Indirect corpus access via third-party content**: an attacker who
  compromises or injects into a vendor's public documentation (which the
  target organization's RAG pipeline indexes) gains indirect write
  access to the target's retrieval corpus with zero direct interaction
  with the target's own systems.

## Bypass
- Keyword/content-based filtering on ingested documents is bypassed by
  the adversarial-passage and black-hole techniques specifically because
  the attack operates in **embedding space**, not surface text — a
  document can read as completely benign to a human or a text-based
  filter while its embedding is deliberately positioned to dominate
  retrieval.
- Document-level access control doesn't stop chunk-level poisoning once
  a document is legitimately ingested (e.g., via a compromised or
  attacker-editable wiki page within an otherwise-trusted source) — the
  access-control boundary and the actual trust boundary aren't aligned.

## Automation
- RevPRAG-style detection tooling analyzes LLM internal activations to
  identify when retrieved content is steering generation anomalously —
  representative of the emerging "detect the attack from the model's
  own internal state" defensive research direction rather than purely
  input-side filtering.
- Adversarial-passage generation itself is an optimization procedure
  (gradient-based or query-based against a surrogate embedding model) —
  attackers can automate crafting a payload with a target query set in
  mind rather than manually authoring content and hoping it ranks well.

## Detection
- Anomaly detection on embedding-space distribution: flag newly-ingested
  vectors whose position is statistically inconsistent with the
  semantic content of their source text (a strong signal of adversarial
  embedding crafting rather than natural language generating that
  embedding).
- Retrieval-result auditing: periodically sample what content is
  actually being retrieved for a representative set of common queries
  and manually/automatically verify it against expected ground truth —
  cheap to run continuously and directly catches both natural poisoning
  and black-hole-style broad hijacking.
- Activation-based detection (RevPRAG direction): monitor the generating
  LLM's own internal activation patterns for signatures consistent with
  processing adversarially-retrieved content, rather than relying solely
  on pre-retrieval input filtering.

## Mitigation
- Track and enforce content provenance through the full pipeline:
  retrieved chunks should carry metadata about their source's trust
  level, and the generating model/orchestration layer should treat
  lower-provenance content with reduced authority (never equal to
  organization-authored source material) rather than flattening all
  retrieved context to the same trust level.
- Isotropy-enhancing post-processing on embeddings (per black-hole-
  attack defense research) reduces the directional-clustering defect
  the attack exploits, though this is a model/infrastructure-level fix
  rather than something an application team can apply unilaterally
  without control over the embedding model.
- Restrict and audit the ingestion pipeline itself: treat "what sources
  feed this corpus" as a security-relevant configuration requiring
  the same review rigor as a new production dependency, especially for
  any source outside direct organizational control (third-party docs,
  public web crawls, user-submitted content).
- Cross-validate retrieval results against a secondary semantic-
  relevance check before feeding them to the generating model, rather
  than trusting raw similarity-score ranking unconditionally.

## Variant Hunting
- Any RAG deployment indexing content the organization doesn't fully
  control the editing history of (third-party docs, crawled web content,
  community wikis, customer-submitted support tickets used for
  training/retrieval) is a candidate for indirect corpus-poisoning via
  that upstream source, independent of the organization's own
  infrastructure security.
- Any vector-store deployment without per-chunk provenance tracking is
  worth flagging even absent a specific known poisoning incident — the
  root cause (flattened trust across retrieved content) is present
  regardless of whether it's been actively exploited yet.

## Related CVEs
- (RAG/vector-DB poisoning is currently studied primarily as an
  ML-security research area rather than tracked via individual product
  CVEs — cross-reference `ai-security/mcp-supply-chain-attacks.md` for
  the adjacent, CVE-tracked AI-infrastructure supply-chain angle.)

## Related Bug Bounty Reports
- (AI/RAG-specific bug bounty disclosures are still uncommon as of
  2026 relative to mature web bug classes — populate with specific
  disclosed findings as found.)

## Related Research
- PoisonedRAG (USENIX Security 2025) — knowledge-corruption attacks via
  small-scale targeted corpus injection.
- Black-Hole Attack (arXiv 2604.05480) — embedding-space anisotropy
  exploitation for broad retrieval hijacking.
- RAGPoison (Snyk Labs) — persistent prompt injection via poisoned
  vector databases.
- RevPRAG (arXiv 2411.18948) — activation-analysis-based poisoning
  detection.
- Semantic Chameleon (arXiv 2603.18034) — corpus-dependent poisoning
  attacks and defenses.
- prompt.security — "The Embedded Threat in Your LLM: Poisoning RAG
  Pipelines via Vector Embeddings."

## Practical Hunting Tips
- When assessing a RAG-based product, map every content source feeding
  the corpus first — the most realistic attack path is very often an
  upstream source the target organization doesn't directly control,
  not the target's own application code.
- Test retrieval behavior with content crafted to be *semantically
  irrelevant but embedding-adjacent* to common queries — this
  specifically probes for the black-hole/adversarial-passage class,
  which purely content-based manual review would never catch.

## Real World Examples
- (Populate with specific disclosed/documented real-world RAG-poisoning
  incidents as found in future research passes — this remains
  predominantly an academic/red-team research area as of 2026 rather
  than one with widely publicized production incidents.)

## References
- https://prompt.security/blog/the-embedded-threat-in-your-llm-poisoning-rag-pipelines-via-vector-embeddings
- https://arxiv.org/pdf/2604.05480
- https://www.usenix.org/system/files/usenixsecurity25-zou-poisonedrag.pdf
- https://labs.snyk.io/resources/ragpoison-prompt-injection/
- https://www.mend.io/blog/vector-and-embedding-weaknesses-in-ai-systems/

---
*Added 2026-09-04 via research pass.*
