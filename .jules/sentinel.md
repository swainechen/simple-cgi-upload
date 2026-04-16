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
