## 2025-01-24 - [Atomic Uploads and Staging for Integrity]
**Vulnerability:** Partially uploaded files and TOCTOU race conditions during file finalization.
**Learning:** Staging file uploads directly to their final destination can lead to incomplete files being accessible if the transfer is interrupted. Furthermore, checking a target path's type (e.g., ensuring it's not a symlink) separately from the write operation introduces a TOCTOU race condition.
**Prevention:** Use `File::Temp` to stage uploads in a secure, private (mode 0600) temporary file within the target directory. Perform all integrity checks (SHA-256) and a final `lstat` verification on the target destination path immediately before using an atomic `rename()` to move the staged file to its final location.
