## 2025-01-24 - [CGI.pm File Upload and Strict Refs]
**Vulnerability:** Path Traversal and XSS in legacy Perl CGI script.
**Learning:** In Perl, using `use strict 'refs'` (often included in `use strict`) prevents using a string as a filehandle. In `CGI.pm`, `$cgi->param('file')` may return a string filename, and attempting to `read()` from it will fail under strict.
**Prevention:** Always use `$cgi->upload('file')` to obtain a proper filehandle for uploads when using modern `CGI.pm` or when `use strict` is enabled.

## 2025-01-24 - [Filename Sanitization and Dotfile Prevention]
**Vulnerability:** Filename-based Path Traversal and Sensitive File Overwrite (e.g., .htaccess).
**Learning:** Even with `basename()`, malicious filenames or special names like `.htaccess` can pose risks if they are used to overwrite configuration files or exploit directory indexing in a shared upload environment.
**Prevention:** Implement a strict whitelist regex for filenames (e.g., `/^[a-zA-Z0-9_\-]+[a-zA-Z0-9_\-\.]*$/`) and explicitly reject filenames starting with a dot.

## 2025-01-24 - [Path Traversal and Whitelisting]
**Vulnerability:** Path traversal in directory parameters.
**Learning:** Using a regex whitelist for directory names can still be risky if the base directory is not correctly managed or if the regex allows directory separators.
**Prevention:** Use a strict lookup table (hash) for allowed directory values and use `File::Spec->catfile` or `File::Spec->catdir` to safely construct paths, ensuring that user-provided segments cannot escape the intended base directory.

## 2025-01-24 - [DoS via Large Uploads and Missing Security Headers]
**Vulnerability:** Denial of Service (DoS) and missing defense-in-depth headers.
**Learning:** Legacy CGI scripts often lack upload size limits, allowing an attacker to exhaust server resources (memory/disk). Additionally, missing modern security headers like `X-Frame-Options` and `CSP` leaves the application vulnerable to clickjacking and XSS.
**Prevention:** Set `$CGI::POST_MAX` to a reasonable limit and handle `cgi_error()` to return a `413 Request Entity Too Large` status. Always include modern security headers (`X-Frame-Options`, `X-Content-Type-Options`, `Content-Security-Policy`) in the CGI response.

## 2025-01-24 - [Stored XSS via SVG Uploads]
**Vulnerability:** Stored Cross-Site Scripting (XSS) through uploaded SVG files.
**Learning:** SVG files are XML-based and can contain embedded <script> tags. When served directly from a server, the browser may execute these scripts in the context of the domain, leading to XSS.
**Prevention:** Include '.svg' in the forbidden file extensions blacklist if SVG support is not strictly required, or implement rigorous SVG sanitization if they must be allowed.

## 2025-01-24 - [Option Injection and Double Extension Bypass]
**Vulnerability:** Command-line option injection via filenames and RCE via double extension bypass.
**Learning:** Filenames starting with a dash (`-`) can be interpreted as flags by system utilities (like `rm` in a cleanup cron job). Furthermore, simple suffix-based extension blacklists can be bypassed on many server configurations using double extensions (e.g., `file.php.txt`).
**Prevention:** Sanitize filenames to disallow leading dashes and dots. Use a robust extension blacklist regex that checks for forbidden extensions followed by either a dot or the end of the string (e.g., `\.(?:php|pl)(?:\.|\z)`).

## 2025-01-24 - [CGI Error Handling and Information Leakage]
**Vulnerability:** Information leakage via Perl's `die` and XSS in error responses.
**Learning:** In Perl CGI, `die` appends the script path and line number unless the string ends with a newline. If headers are already sent, this info is leaked to the browser. Also, `cgi_error()` messages from `CGI.pm` can be reflected in the response, creating an XSS vector if not escaped.
**Prevention:** Always append `\n` to `die` messages in CGI scripts. Always escape `cgi_error()` output with `$cgi->escapeHTML()`. Prefer reflected output based on sanitized internal state (e.g., the final `$filename`) rather than raw request parameters.

## 2026-04-23 - [Secure File Creation and Symlink Protection]
**Vulnerability:** Symlink attack and race conditions in file upload.
**Learning:** Standard Perl `open` with `>` is vulnerable to symlink following and race conditions. Using `sysopen` with `O_NOFOLLOW` prevents following symlinks. To maintain overwrite functionality without `O_EXCL`, `O_TRUNC` can be used. Furthermore, `O_NOFOLLOW` is not always in the default `Fcntl` export and should be imported explicitly.
**Prevention:** Use `sysopen` with `O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW` and explicit mode (e.g., `0644`) for secure file creation that allows overwriting. Always explicitly import `O_NOFOLLOW` from `Fcntl`.
## 2025-01-24 - [Symlink Attacks and Accidental Overwrites]
**Vulnerability:** Symlink attack allowing overwriting sensitive files and accidental file overwrite.
**Learning:** Standard 3-argument `open` with `>` will follow symlinks and overwrite existing files. This can be exploited if an attacker can pre-create a symlink in the upload directory pointing to a sensitive file.
**Prevention:** Use `sysopen` with `O_CREAT | O_EXCL` to ensure the file is created only if it doesn't exist. Use `O_NOFOLLOW` (where supported) to explicitly prevent following symlinks.

## 2026-04-24 - [Centralized Error Handling and Security Headers]
**Vulnerability:** Inconsistent security headers and improper HTTP status codes in error responses.
**Learning:** Legacy CGI scripts often print error messages directly before headers are sent or omit security headers in error paths. Furthermore, returning `200 OK` for validation failures (like invalid filenames) is poor practice and can interfere with automated security scanning.
**Prevention:** Implement a centralized `send_error` function that emits proper HTTP status codes (400, 403, 500) and includes a full set of modern security headers (CSP, HSTS, X-Frame-Options) for every response, ensuring consistent protection across all code paths.

## 2026-04-24 - [CGI.pm Header Normalization and Duplicate Headers]
**Vulnerability:** Security policy bypass via duplicate HTTP headers.
**Learning:** In Perl's `CGI.pm`, header names can be passed as `-Header_Name` or `-Header-Name`. If both are present in the header hash (e.g., a default using underscores and an override using dashes), `CGI.pm` treats them as distinct keys and may output both headers. Browsers may then ignore the more restrictive header. Additionally, case sensitivity in keys can also lead to duplicates.
**Prevention:** Normalize all header keys by converting to lowercase and replacing dashes with underscores before passing them to the `$cgi->header()` function to ensure that overrides correctly replace default values instead of creating duplicates.

## 2025-05-20 - [Complex Security Header Parsing (CSP/Permissions-Policy)]
**Vulnerability:** Broken or weakened security policies due to improper parsing of multi-part headers.
**Learning:** Security headers like `Content-Security-Policy` often contain both semicolons and colons (e.g., in `connect-src https://example.com`). A naive parser that splits only on semicolons or incorrectly identifies colons as header-value separators will break these directives.
**Prevention:** Use a whitelist of recognized security headers to distinguish between a new HTTP header and a continuation of a multi-part value. Ensure that subsequent parts of a multi-part header are correctly appended to the preceding recognized header key.

## 2025-05-15 - [DoS via Parameter Inflation and Log Traceability]
**Vulnerability:** Denial of Service via excessive form parameters or multipart records, and difficult audit log correlation.
**Learning:** `CGI.pm` by default may not limit the number of parameters or multipart records, allowing an attacker to consume memory and CPU. Additionally, inconsistent log formats make it harder for automated tools to trace malicious activity.
**Prevention:** Set `$CGI::MAX_PARAMS` and `$CGI::MAX_MULTIPART_RECORDS` to sensible limits. Standardize security logs to start with the sanitized remote IP for consistent traceability and easier parsing by security monitoring tools.

## 2025-05-21 - [CGI Hardening and Search Engine Exclusion]
**Vulnerability:** Potential for parameter inflation attacks and unintentional indexing of private upload utility.
**Learning:** Default CGI.pm settings may allow a high number of parameters, increasing DoS risk. Furthermore, without explicit instructions, search engines may index the application and its error pages, exposing the tool to a wider audience than intended.
**Prevention:** Set `$CGI::MAX_PARAMS` to a strict minimum (e.g., 10) and enable `$CGI::LIST_CONTEXT_WARN` to catch unsafe parameter handling. Always include `X-Robots-Tag: noindex, nofollow` in default security headers for private utilities.

## 2025-05-22 - [Complex Security Header Parsing (CSP/Permissions-Policy)]
**Vulnerability:** Broken or weakened security policies due to improper parsing of multi-part headers containing colons.
**Learning:** Security headers like `Content-Security-Policy` and `X-Robots-Tag` often contain colons in their directives (e.g., `connect-src https://...`). A parser that interprets any "name: value" pattern as a new HTTP header might misidentify these directives as unknown headers and drop subsequent parts of the policy.
**Prevention:** Implement a lenient parsing mode for recognized multi-part headers. If an entry looks like a header but the name is unrecognized, it should still be appended to the current header if that header is known to contain colons in its directives.

## 2025-01-24 - [Fatal Permission Enforcement in Shared Directories]
**Vulnerability:** Insecure file permissions in shared upload directories.
**Learning:** In a world-writable directory (like `777` suggested for `incoming`), failing to fatalize `chmod` allows attackers to pre-create files with loose permissions (e.g., `0666`). Even if the web server overwrites the content, it cannot tighten permissions if it doesn't own the file, leaving uploads readable by others.
**Prevention:** Always make `chmod` failures fatal when enforcing security policies on uploaded files. Ensure the partial or insecurely-permissioned file is removed before returning an error.

## 2026-04-25 - [DoS via Disk Exhaustion (File Count)]
**Vulnerability:** Denial of Service (DoS) via unlimited file uploads.
**Learning:** Even with individual file size limits, an attacker can still exhaust disk space or inodes by uploading a large number of small files.
**Prevention:** Implement a per-directory maximum file count limit in the CGI script. Ensure the check distinguishes between new uploads and overwrites (using `! -e $path`) to avoid blocking legitimate updates while enforcing the overall storage policy.
