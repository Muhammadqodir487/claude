# File Upload leading to Remote Code Execution

## Summary
A file upload feature becomes an RCE primitive once the server stores
attacker-controlled bytes somewhere it (or a downstream parser) will
later execute or reinterpret as code, and its "is this file safe" check
relies on spoofable signals — client-sent `Content-Type`, filename
extension, or the first few bytes — rather than verified content. Almost
none of this needs a memory-safety bug: most 2025-2026 file-upload RCEs
are pure trust failures, which is why the same bypass patterns
(extension games, MIME spoofing, magic-byte polyglots, archive path
traversal) recur across unrelated codebases and languages. It shares its
root cause with **Deserialization** (`web-security/deserialization.md`)
— "attacker-controlled content fed to a trusted parser" — and an
"import from URL" upload feature is often literally an **SSRF**
(`web-security/ssrf.md`) primitive wearing a file-upload costume.

## Root Cause
- **Web-executable upload directory**: uploads land in a path the web
  server is configured to execute (PHP/JSP/ASP handlers wired to the
  same tree as `/uploads/`), so landing any server-script extension on
  disk is enough.
- **Trust in client-supplied metadata**: validating type via the
  `Content-Type` header or filename extension the client sent, rather
  than actual file content — both fully attacker-controlled.
- **Image/media library parser bugs**: ImageMagick, ffmpeg, and libvips
  parse complex, under-fuzzed formats; a memory-corruption bug in the
  parser turns even a correctly-rejected upload into RCE once the server
  "helpfully" re-processes it (thumbnailing, conversion, EXIF stripping).
- **Archive extraction without path sanitization ("zip slip")**: a
  feature that auto-extracts an uploaded `.zip`/`.tar` trusts embedded
  entry paths; `../` sequences let the attacker choose the extraction
  destination, including inside the webroot.
- **Cloud storage misconfig / import-from-URL combo**: a public-write
  S3-style bucket fronted by a CDN/edge layer serving an interpreted
  content type turns "anyone can upload" into "anyone can serve logic
  from our domain"; a server-side "import from URL" feature inherits
  SSRF on the fetch side and unrestricted upload on the storage side.

## Attack Flow
1. Enumerate every upload surface, not just "upload avatar" — profile
   pictures, attachments, import-from-URL fields, bulk-import (CSV/XLSX)
   parsers, and theme/plugin installers found via crawling/JS analysis.
2. Determine where the file is stored and whether that path is
   web-reachable and execution-enabled — fetch the file back immediately
   after upload to confirm reachability before attempting bypasses.
3. Probe what the validation actually checks: swap `Content-Type` alone,
   swap the extension alone, swap both while keeping the magic bytes
   intact — whichever combination succeeds reveals the trusted signal.
4. Once an executable extension lands with executable content, request
   it directly and confirm execution with a benign command (`id`) or an
   OOB DNS/HTTP callback before pursuing further impact.

## Exploitation
- **Apache Tomcat partial PUT RCE (CVE-2025-24813)**: with the default
  servlet write-enabled (`readonly=false`) and partial PUT on (default),
  an attacker PUTs a file with an internal dot in its name, then — with
  file-based session persistence enabled — plants a malicious serialized
  session file via PUT and triggers its deserialization, reaching
  unauthenticated RCE with no traditional webshell extension involved.
- **Craft CMS pre-auth RCE (CVE-2025-32432, CVSS 10.0)**: exploited as a
  zero-day from mid-February 2025 (Orange Cyberdefense); a misconfigured
  image-transform endpoint lets an attacker plant PHP into a session
  file via a crafted URL, then abuse a `__class` bypass in that endpoint
  to force-load the `PhpManager` gadget and execute it — roughly 13,000
  instances were vulnerable, ~300 confirmed compromised.
- **WordPress plugin ecosystem, 2025**: unauthenticated arbitrary upload
  is one of the most common critical WP-plugin findings — CVE-2025-7340
  (HT Contact Form Widget, 250K+ installs) had zero file-type checking;
  CVE-2025-7847, CVE-2025-2512, and CVE-2025-6679 (AI Engine, File Away,
  Bit Form) all reached RCE via low-privilege or unauthenticated uploads.
- **MojoPortal zip slip (CVE-2025-69770)**: skin-upload extracts a
  `.zip` without validating entry paths, writing into the webroot via
  `../../../` sequences. **ImageMagick (CVE-2025-57807, CVE-2025-55298)**:
  a heap OOB write in `SeekBlob()`/`WriteBlob()` and a format-string bug
  in `InterpretImageFilename()`, both reachable by processing an upload.

## Bypass
- **Extension blacklist bypass**: alternate server-executable extensions
  the blacklist forgot (`.phtml`, `.pht`, `.phar`, `.php5`), case
  variation, and trailing dots/spaces/`::$DATA` on Windows/NTFS, which
  the OS strips or reinterprets after the check has already passed
  (`shell.asp::$DATA` reads back as `shell.asp`).
- **MIME-type / magic-byte spoofing**: setting `Content-Type: image/jpeg`
  regardless of content defeats header-based checks; prepending real
  magic bytes of an allowed format defeats first-bytes-only checks —
  exactly how CVE-2025-58745 (WeGIA) bypassed the fix for
  CVE-2025-22133: a PHP webshell prefixed with `.xlsx` magic bytes
  passed MIME detection and was still saved as `.php`.
- **Polyglot files**: bytes simultaneously valid as an allowed format
  and executable code — `GIF89a<?php system($_GET['c']);?>` is a valid
  GIF to any signature check yet still executes as PHP given a `.php`
  extension; EXIF-metadata injection hides a payload inside a genuinely
  valid JPEG for chaining with a local-file-include read.
- **Filename injection and SSRF-via-import**: doubled extensions
  (`shell.jpg.php`) smuggle a different effective extension than the one
  validated; CVE-2025-12138 (WordPress URL Image Importer) trusted the
  *remote server's* `Content-Type` header, attacker-controlled when the
  importer is pointed at the attacker's own server.
- **Race condition between upload and re-validation**: on stacks that
  upload first and asynchronously scan/move the file afterward,
  requesting it by its predictable temp path during that window can
  retrieve or trigger content that would be rejected moments later — the
  same TOCTOU pattern as `web-security/race-conditions.md`.

## Automation
- **Burp Suite Upload Scanner** (PortSwigger/modzero) and the companion
  **file-upload-traverser** extension — purpose-built since generic
  scanners don't adapt to multipart flows; automate extension/MIME/
  magic-byte fuzzing, PHP/JSP/ASP/XXE/SSRF/XSS/SSI injection, and
  path-traversal-via-filename checks.
- Custom extension x MIME x magic-byte wordlist matrices driven through
  Intruder/ffuf to map exactly which blacklist entries were missed, and
  open-source polyglot-generator scripts to produce ready-made test
  files instead of hand-crafting each one.

## Detection
- Content-based validation at the gateway: verify magic bytes *and*
  that the file fully parses as a well-formed instance of the claimed
  format — catches polyglots that pass a header-only check. Filesystem/
  EDR monitoring for new server-executable-extension files in upload
  directories, and processes spawned by the web-server worker with a
  parent path inside an uploads tree, is a strong bypass-independent
  signal.
- Archive-extraction instrumentation alerting on any resolved
  destination outside the intended root (catches zip-slip regardless of
  encoding), plus outbound-request monitoring on import-from-URL
  features exactly as for SSRF generally.

## Mitigation
- **Never execute code from the upload directory** — store uploads
  outside the webroot, or disable script execution for that path at the
  web-server config level (Apache: `RemoveHandler`/engine off; Nginx: no
  handler location block routing that path to FastCGI).
- Rename stored files to a random name with no attacker-influenced
  extension and serve them from a separate cookieless, no-script domain,
  so a successfully-uploaded malicious file still can't execute in the
  application's own origin/session context.
- Validate by actually parsing the claimed format and, where feasible,
  re-encode uploaded images server-side — a freshly re-generated file
  strips polyglot payloads riding in metadata/trailing bytes. Keep
  media libraries patched and sandboxed, since parser-level RCEs are
  independent of any extension/MIME bypass logic.
- Normalize every archive entry path before extraction, rejecting
  anything resolving outside the extraction root; never grant public
  write on a content-serving cloud bucket, and force `Content-Type` at
  the CDN/edge layer rather than from user input.

## Variant Hunting
- Test bulk-import endpoints (CSV/XLSX/XML) with the same magic-byte-
  prefix trick that broke WeGIA — import features are often
  threat-modeled as a data problem, not a file-upload problem, and get
  weaker validation than dedicated "upload a picture" features.
- Re-test any upload "fixed" by adding only a MIME/extension check
  without full-content validation — a narrow patch routinely gets
  bypassed again with a different magic-byte prefix.
- Treat every "import from URL" feature as two bugs: SSRF (can the
  fetch reach internal/metadata endpoints?) and unrestricted upload
  (does the fetched content get the same validation as a direct
  multipart upload?). Check theme/plugin/installer features the same
  way — they auto-extract a `.zip` and are rarely threat-modeled as
  upload surface despite being structurally identical to one.

## Related CVEs
- CVE-2025-24813 — Apache Tomcat, unauthenticated RCE via partial PUT +
  file-based session deserialization (raised CVSS 5.5 to 9.8).
- CVE-2025-32432 — Craft CMS, pre-auth RCE via image-transform `__class`
  bypass chained to a planted session-file payload, CVSS 10.0.
- CVE-2025-58745 (bypassing the fix for CVE-2025-22133) — WeGIA,
  magic-byte-prefixed PHP webshell defeating post-patch MIME validation.
- CVE-2025-69770 — MojoPortal CMS, zip-slip RCE via skin-upload
  extraction.
- CVE-2025-7847 / CVE-2025-7340 / CVE-2025-2512 / CVE-2025-6679 —
  WordPress AI Engine, HT Contact Form Widget, File Away, and Bit Form
  plugins, unauthenticated/low-privilege arbitrary file upload to RCE.
- CVE-2025-12138 — WordPress URL Image Importer, remote-Content-Type
  trust in an import-from-URL flow (SSRF+upload combo).
- CVE-2025-57807 / CVE-2025-55298 — ImageMagick memory-corruption RCEs
  reachable via routine image processing.

## Related Bug Bounty Reports
- HackerOne Report #1027822 — Starbucks (`mobile.starbucks.com.sg`), an
  `.ashx` endpoint intended only for images accepted unrestricted file
  types, Critical (9.8), $5,600 bounty.
- HackerOne — TikTok report: SSRF and local-file-read via video upload
  through vulnerable FFmpeg HLS processing ($2,727), a concrete instance
  of the "media-processing library bug reached via upload" pattern.
- HackerOne Report #3031518 — Internet Bug Bounty disclosure of
  CVE-2025-24813 (Tomcat partial PUT RCE), $4,323 bounty.

## Related Research
- PortSwigger Web Security Academy — "File upload vulnerabilities"
  learning path and labs (extension blacklist bypass, Content-Type
  bypass, RCE via web shell upload).
- modzero/PortSwigger — Upload Scanner research on automating
  upload-specific attack classes generic scanners miss; Vickie Li —
  "Polyglot Files: a Hacker's Best Friend."
- This KB's `web-security/deserialization.md` — the Tomcat and Craft CMS
  cases above are both "upload primitive feeding a second, trusted
  deserialization/gadget-loading sink," the same pattern as SharePoint
  ToolShell. `web-security/ssrf.md` — import-from-URL upload features
  are a direct instance of the "server fetches a user-influenced URL"
  root cause described there, with a storage step attached.

## Practical Hunting Tips
- Fetch the file back immediately after upload rather than assuming
  rejection — some frameworks store a file while returning a generic
  error, leaving it sitting in a web-reachable path.
- Test each validation layer independently and combined (Content-Type
  alone, extension alone, magic bytes alone, then all three
  consistent-but-wrong) — the specific gap tells you which bypass class
  to focus on. Grep client-side JS/API specs for `multipart/form-data`,
  `import`, or `*_url`-style parameters, since import-from-URL paths are
  underreported.
- When a prior upload finding was "fixed," re-test with a different
  bypass technique than the one originally reported — narrow,
  bypass-specific patches are the norm in this bug class, not fully
  closed root causes.

## Real World Examples
- Craft CMS CVE-2025-32432 — zero-day exploitation from mid-February
  2025, ~13,000 vulnerable and ~300 compromised internet-facing
  instances by mid-April 2025, chaining an image-transform upload
  primitive into pre-auth RCE.
- Apache Tomcat CVE-2025-24813 — severity re-rated from 5.5 to 9.8
  within days of a public PoC, actively targeted against write-enabled
  default-servlet Tomcat deployments; Starbucks HackerOne Report
  #1027822 shows the same bug class reaching large, actively-monitored
  production consumer brands, not just legacy/niche software.

## References
- https://www.rapid7.com/blog/post/2025/03/19/etr-apache-tomcat-cve-2025-24813-what-you-need-to-know/
- https://github.com/advisories/GHSA-83qj-6fr2-vhqg
- https://sensepost.com/blog/2025/investigating-an-in-the-wild-campaign-using-rce-in-craftcms/
- https://socprime.com/blog/cve-2025-32432-rce-vulnerability-in-craft-cms/
- https://github.com/LabRedesCefetRJ/WeGIA/security/advisories/GHSA-hq96-gvmx-qrwp
- https://www.sentinelone.com/vulnerability-database/cve-2025-69770/
- https://zeropath.com/blog/cve-2025-12138-wordpress-url-image-importer-arbitrary-file-upload
- https://www.sentinelone.com/vulnerability-database/cve-2025-57807/
- https://hackerone.com/reports/1027822
- https://github.com/reddelexc/hackerone-reports/blob/master/tops_by_bug_type/TOPUPLOAD.md
- https://portswigger.net/web-security/file-upload
- https://portswigger.net/bappstore/b2244cbb6953442cb3c82fa0a0d908fa
- https://vickieli.dev/hacking/polyglot/

---
*Added 2026-09-04 via research pass.*
