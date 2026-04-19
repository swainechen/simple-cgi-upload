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
