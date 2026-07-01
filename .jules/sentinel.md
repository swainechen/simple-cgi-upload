## 2025-01-24 - [Atomic Uploads and Staging for Integrity]
**Vulnerability:** Partially uploaded files and TOCTOU race conditions during file finalization.
**Learning:** Staging file uploads directly to their final destination can lead to incomplete files being accessible if the transfer is interrupted. Furthermore, checking a target path's type (e.g., ensuring it's not a symlink) separately from the write operation introduces a TOCTOU race condition.
**Prevention:** Use `File::Temp` to stage uploads in a secure, private (mode 0600) temporary file within the target directory. Perform all integrity checks (SHA-256) and a final `lstat` verification on the target destination path immediately before using an atomic `rename()` to move the staged file to its final location.

## 2025-01-24 - [DoS Risk from Early CGI Body Parsing]
**Vulnerability:** Resource exhaustion (DoS) due to `CGI.pm` parsing request bodies for invalid HTTP methods or Content-Types.
**Learning:** Initializing the `CGI` object in Perl before validating `REQUEST_METHOD` and `CONTENT_TYPE` allows the module to consume resources (memory/disk) parsing a large request body even if the request is destined to be rejected. Furthermore, creating a `CGI` object in error handlers can trigger this same parsing if not carefully controlled.
**Prevention:** Validate `REQUEST_METHOD` and `CONTENT_TYPE` using environment variables *before* instantiating the `CGI` object. In error handlers, explicitly set `$CGI::POST_MAX = 0` before creating a `CGI` object to ensure it only handles header generation and does not attempt to parse the request body.
