# Server-Side Template Injection (SSTI)

## Summary
SSTI occurs when user input is concatenated into a template *string*
that a template engine then compiles and executes, rather than being
passed in as *data* rendered by an already-compiled template. Because
most modern template engines (Jinja2, Twig, FreeMarker, Velocity,
Handlebars server-side) are Turing-complete-adjacent by design — they
need attribute access, method calls, and sometimes arbitrary expression
evaluation to be useful — a successful injection routinely escalates
straight to full RCE, not just output manipulation. It's one of the
few web bug classes where "found the injection" and "have a shell"
are often only one payload away from each other.

## Root Cause
- Untrusted input reaches a template-engine's *render-a-string-as-a-
  template* API (e.g., Flask/Jinja2's `render_template_string(user_input)`
  instead of `render_template("fixed.html", value=user_input)`) — the
  single structural mistake underlying essentially every SSTI, regardless
  of engine.
- Template engines expose attribute/method traversal (Python's
  `__class__`, `__mro__`, `__subclasses__`; Java's reflection-adjacent
  helpers) specifically so templates can call into application objects
  usefully — the same mechanism attackers walk to reach
  `os.system`-equivalent sinks from an initial injection point with no
  direct code-execution primitive of its own.
- "Sandboxed" template modes (e.g., Jinja2's `SandboxedEnvironment`)
  reduce but don't eliminate this surface — sandbox escapes are a
  standing, actively-researched sub-field precisely because the sandbox
  has to keep enough dynamic-attribute-access power to remain useful for
  legitimate templates.

## Attack Flow
1. Detect the injection with an arithmetic-evaluation probe
   (`{{7*7}}` for Jinja2/Twig-family syntax, `${7*7}` for
   FreeMarker/Velocity/EL-family syntax, `#{7*7}` for Ruby ERB/Slim) —
   if the output contains `49` instead of the literal probe string, the
   input is being compiled and executed as a template, not just escaped
   as data.
2. Fingerprint the specific engine from syntax/error-message differences
   (each engine has distinct delimiter syntax and distinct error
   messages on a malformed expression) — the exploitation path is
   entirely engine-specific from here on.
3. Walk the engine's object graph from whatever object is in scope
   (often just the built-in string/int type your probe payload already
   evaluated against) to a code-execution primitive — for Python/Jinja2,
   the canonical chain is `''.__class__.__mro__[1].__subclasses__()`
   enumerated to find a subprocess-capable class.
4. Confirm RCE with an out-of-band callback (DNS/HTTP) before attempting
   anything with real impact, exactly as with any other suspected RCE
   primitive.

## Exploitation
- **Jinja2 (Python)**: `{{ ''.__class__.__mro__[1].__subclasses__() }}`
  to enumerate subclasses, then index to a class exposing
  `__init__.__globals__` containing `os`/`subprocess`, reaching
  arbitrary command execution. Tplmap automates engine fingerprinting
  and this chain across common Python template engines.
- **Pipe-filter attribute access (bypass-oriented)**: Jinja2's pipe
  filters can reach attributes without ever writing the literal
  forbidden string — `{{ ''|attr('__class__') }}` retrieves `__class__`
  while the substring `.__class__` never appears anywhere in the
  payload, defeating naive substring-based blocklists.
- **FreeMarker/Velocity (Java)**: reach
  `freemarker.template.utility.Execute` (or equivalent built-in utility
  classes) via the template's object-model traversal to invoke arbitrary
  system commands — conceptually identical to the Python chain, just
  walking Java's reflection surface instead of Python's `__mro__`.

## Bypass
- **Hexadecimal/Unicode character encoding**: representing underscores
  or brace delimiters via `\x5f`-style hex escapes or Unicode look-alike
  characters that the template engine still parses identically, but that
  a naive regex/blocklist WAF rule doesn't recognize as the blocked
  literal character.
- **Filter/attribute-access chaining instead of literal dunder syntax**:
  as above, using the engine's own indirection features (pipe filters,
  bracket-notation attribute access) to reach the same destination
  object without the payload ever containing the specific substring a
  blocklist is looking for.
- Sandboxed-environment escapes: published research (Tplmap, and
  engine-specific sandbox-escape write-ups) documents concrete
  bypasses of "sandboxed" Jinja2/Twig configurations — never assume
  "sandboxed" template mode fully closes the RCE path without checking
  the specific sandbox implementation's known bypass history.

## Automation
- **Tplmap** — automates engine fingerprinting and exploitation chain
  selection across the common Python/Java/JS/Ruby template engines,
  analogous to sqlmap for SQLi.
- PayloadsAllTheThings' SSTI section is the standard maintained payload
  reference across engines — use it to quickly build an engine-specific
  probe/exploit list rather than re-deriving syntax from scratch per
  engagement.

## Detection
- WAF/IDS rules matching literal `{{`, `${`, `#{`, `<%` sequences in
  user-controllable input fields catch naive attempts but are routinely
  defeated by the encoding/filter-chaining bypasses above — treat
  signature-based SSTI detection as a first filter, not a guarantee.
- Runtime: alert on template-engine render calls where the *template
  source itself* (not just render variables) varies per-request — a
  correctly-architected application renders a small, fixed set of
  template files, so a render call with per-request-varying template
  source is itself an anomaly worth flagging independent of payload
  content.

## Mitigation
- **Structural fix, not a filter**: never pass user input into a
  template-compilation API as the template string itself. Always render
  a fixed, developer-authored template file and pass untrusted input
  only as a *variable* the template displays — this closes the entire
  bug class architecturally rather than trying to filter dangerous
  syntax out of untrusted input.
- Where user-influenced template content is a genuine product
  requirement (e.g., customizable email templates), use a logic-less
  template language with no attribute/method-traversal capability at
  all (e.g., Mustache) rather than a full-featured engine in "sandboxed"
  mode.

## Variant Hunting
- Any feature allowing user-supplied "custom templates," "email
  templates," "report templates," or "notification formatting" is a
  candidate for this bug class — check whether the customization value
  is rendered as a template string or passed as data to a fixed
  template.
- Re-test previously-"fixed" SSTI findings that were closed via a
  blocklist/regex filter rather than the structural fix above — per the
  bypass techniques documented above, blocklist-based SSTI fixes have a
  poor track record of being complete.

## Related CVEs
- (Populate with specific CVEs as found in future research passes —
  SSTI in specific products/frameworks recurs regularly; search
  "template injection" + current year on NVD/CISA KEV for live examples.)

## Related Bug Bounty Reports
- (Populate as specific disclosed SSTI reports are found — Intigriti's
  and PortSwigger's own research blogs are strong sources for
  disclosed/documented cases.)

## Related Research
- Vladislav Korchagin (2026-01-03) — "Successful Errors: New Code
  Injection and SSTI Techniques."
- Intigriti — "Server-Side Template Injection (SSTI): Advanced
  Exploitation Guide."
- PayloadsAllTheThings — SSTI reference (swisskyrepo).

## Practical Hunting Tips
- Test the arithmetic-probe payload for *every* template-syntax family
  (`{{}}`, `${}`, `#{}`, `<%%>`) against any input field that ends up
  rendered back to the user with any formatting/templating applied —
  don't assume the framework's "obvious" syntax is the only one in use,
  since applications sometimes layer multiple template engines.
- When a blocklist-based SSTI defense is encountered, specifically try
  the filter/pipe-based attribute access technique before concluding the
  target is unexploitable — this bypass class is underused relative to
  how reliably it defeats naive blocklists.

## Real World Examples
- (Populate incrementally with specific disclosed real-world SSTI
  incidents/CVEs as found in future passes.)

## References
- https://onsecurity.io/article/server-side-template-injection-with-jinja2/
- https://www.intigriti.com/researchers/blog/hacking-tools/exploiting-server-side-template-injection-ssti
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection
- https://www.thehacker.recipes/web/inputs/ssti

---
*Added 2026-09-04 via research pass.*
