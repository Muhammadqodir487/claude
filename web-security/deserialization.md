# Insecure Deserialization

## Summary
Deserialization turns a byte stream back into live objects — and in
every mainstream serialization format that supports rich object graphs
(Java's native serialization, PHP's `unserialize`, Python's `pickle`,
.NET's `BinaryFormatter`/ViewState, Ruby's `Marshal`), reconstructing an
object can invoke constructors, magic methods (`__wakeup`, `__destruct`,
`readObject`), and property setters as a side effect of simply *existing
as that type*. When the byte stream comes from an untrusted source, an
attacker doesn't need to find a bug in any single class — they need to
find a **gadget chain**: a sequence of already-present, individually
"safe" classes whose deserialization side effects chain together into
arbitrary behavior, most commonly RCE. This is what makes deserialization
uniquely dangerous relative to most other injection classes: the
exploit primitive is built entirely from code the application already
trusts.

## Root Cause
- Native/rich serialization formats are used across a trust boundary
  (accepting a serialized blob from a cookie, a hidden form field, an
  API body, or inter-service messaging) without verifying the sender is
  trusted — the deserializer has no way to distinguish "a blob I
  produced earlier" from "a blob an attacker crafted from scratch."
- The deserialization API itself doesn't restrict *which* classes may be
  instantiated — by default it will happily instantiate anything on the
  classpath/environment that matches the type information embedded in
  the serialized data, including classes never intended to be
  deserialization entry points.
- Gadget chains exploit **legitimate classes already present** (common
  utility/collection libraries, ORM proxies, logging frameworks) — the
  vulnerability isn't in any single gadget class's own logic, it's in
  the *combination* being reachable from a deserialization entry point
  at all.

## Attack Flow
1. Identify a deserialization entry point: a cookie/parameter/header
   that decodes to a recognizable serialized format (Java serialized
   objects start with `\xAC\xED\x00\x05`; PHP serialized strings have a
   distinctive `a:`/`O:`/`s:` structure; .NET ViewState is base64 with a
   recognizable structure once decoded and, if unprotected, no MAC).
2. Fingerprint the language/framework and enumerate what gadget-chain
   libraries (widely-used dependencies like Java's Commons Collections,
   Spring, or the target's ORM) are actually present on the classpath —
   the chain that works is entirely dependent on what's actually
   loaded, not universal.
3. Generate or select a known gadget chain for that specific combination
   of libraries (tools like `ysoserial` for Java maintain a large catalog
   of pre-built chains per library combination) and serialize a payload
   using that chain.
4. Deliver the crafted serialized blob to the identified entry point and
   confirm execution via an out-of-band callback before pursuing further
   impact.

## Exploitation
- **SharePoint "ToolShell" (CVE-2025-53770)**: unauthenticated attackers
  POST a crafted request whose `__VIEWSTATE` carries a deserialization
  payload chaining `TextFormattingRunProperties` → XAML parsing →
  `Process.Start`, achieving unauthenticated RCE. Check Point Research
  observed 4,600+ compromise attempts across 300+ organizations within a
  single week of public disclosure — a clean illustration of how fast
  deserialization RCEs get weaponized at scale once a working chain is
  public.
- **Java Commons-Collections-style gadget chains**: the canonical
  teaching example — `InvokerTransformer`/`ChainedTransformer` chains
  present in Commons Collections let an attacker-controlled
  deserialized object invoke arbitrary method calls (ultimately reaching
  `Runtime.exec`) purely through legitimate transformer-composition
  functionality never intended as an RCE primitive.
- **CVE-2025-49597 (goodby-csv, PHP Composer package)**: a gadget chain
  in a CSV-handling library enabling RCE via PHP object injection —
  illustrates that gadget-chain risk isn't confined to "big" frameworks;
  any sufficiently-used utility library with magic methods can become
  part of a chain.
- **Python pickle RCE**: `pickle.loads()` on untrusted data can invoke
  `__reduce__` on a crafted object to execute arbitrary code directly at
  deserialization time — one of the most direct language-level
  deserialization RCEs, with no "gadget chain" hunting required since
  `__reduce__` is a first-class code-execution hook by design.

## Bypass
- **Blocklist-based class filtering**: deserialization filters that
  block a known-dangerous class name are routinely bypassed by finding
  an *alternate* gadget chain using different classes not on the
  blocklist — the underlying primitive (untrusted deserialization
  reaching arbitrary code) isn't fixed by blocking specific known
  payloads.
- **ViewState without MAC/encryption**: if `.NET` ViewState MAC
  validation is disabled or a leaked machine key is available, an
  attacker can forge a validly-signed malicious ViewState payload,
  bypassing the integrity control the platform relies on to prevent
  exactly this class of attack.

## Automation
- **ysoserial** (Java) and **ysoserial.net** (.NET) — generate
  ready-to-use serialized payloads for dozens of known gadget chains
  across common library combinations; the standard first tool to reach
  for once a Java/.NET deserialization entry point is confirmed.
- Static analysis: grep dependency manifests for known-vulnerable
  gadget-source libraries (specific Commons Collections versions,
  vulnerable ORM versions) as a fast triage signal before manual dynamic
  testing.

## Detection
- Signature/format detection on inbound fields: flag any
  cookie/parameter/header value matching a known native-serialization
  byte pattern in a context where the application shouldn't be sending
  users raw serialized objects to round-trip.
- Runtime instrumentation (RASP-style) hooking deserialization APIs
  directly to block instantiation of known-dangerous gadget classes at
  the moment of deserialization, independent of what value made it
  through network-level filtering.

## Mitigation
- **Don't deserialize untrusted data into rich objects at all** — the
  only fully reliable fix. Use a data-only format with a strict schema
  (JSON validated against a schema, protobuf with a fixed message
  definition) for anything crossing a trust boundary, since these
  formats have no equivalent to constructor/magic-method side effects.
- Where native serialization must be kept for compatibility, use an
  allowlist (not blocklist) of exactly the classes expected to be
  deserialized, rejecting anything else outright.
- For .NET ViewState specifically: always enable MAC validation and
  rotate/protect machine keys — a leaked machine key defeats the primary
  control meant to prevent forged ViewState payloads entirely.

## Variant Hunting
- Any endpoint accepting a cookie/parameter that looks like an opaque
  "state" or "token" blob is worth checking for a serialization format
  underneath the encoding, even when it's not obviously labeled as such.
- After confirming one gadget chain works, check whether the same
  library combination is used in *other* deserialization entry points
  across the same application/organization — a shared internal library
  or shared classpath means the same chain often works across many
  services, not just the one first found.
- Re-examine any library previously used as a gadget source (Commons
  Collections, common CSV/YAML/serialization utility libraries) for
  *new* magic-method chains after any refactor — adding new
  transformer-like/reflective functionality to a widely-used library can
  introduce a fresh gadget even without any bug in the new code itself.

## Related CVEs
- CVE-2025-53770 — SharePoint "ToolShell," unauthenticated RCE via
  ViewState deserialization, 4,600+ observed compromise attempts across
  300+ organizations within a week.
- CVE-2025-49597 — goodby-csv (PHP), gadget chain enabling RCE via
  object injection.

## Related Bug Bounty Reports
- (Populate as specific disclosed deserialization reports are found —
  HackerOne Hacktivity and PortSwigger's research blog are strong
  sources.)

## Related Research
- ysoserial / ysoserial.net — canonical gadget-chain payload generators.
- jsmon.sh — "Deserialization Attacks: Java Gadget Chains, Python Pickle
  RCE & .NET ViewState."

## Practical Hunting Tips
- Don't stop at confirming deserialization is happening — confirm which
  *specific* libraries are on the classpath/environment before assuming
  no gadget chain exists; "no known ysoserial chain worked" often means
  "the right chain for this exact library combination hasn't been
  published yet," not "this target is safe."
- Treat any "opaque state token" field as a deserialization candidate
  by default until proven otherwise — this bug class is systematically
  underreported because these fields don't look like typical injection
  points at a glance.

## Real World Examples
- CVE-2025-53770 (SharePoint ToolShell) — mass-exploited within a week
  of disclosure, one of the highest-velocity deserialization RCE
  weaponization timelines on record.

## References
- https://blogs.jsmon.sh/deserialization-attacks-java-gadget-chains-python-pickle-rce-net-viewstate/
- https://securelayer7.net/learn/web-exploitation/what-is-insecure-deserialization
- https://advisories.gitlab.com/pkg/composer/handcraftedinthealps/goodby-csv/CVE-2025-49597/

---
*Added 2026-09-04 via research pass.*
