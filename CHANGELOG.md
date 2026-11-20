# Changelog

## 4.0.0 - 2026-11-20

- Added a machine-readable authorization scope template and `scope_guard.py`.
- Made TLS verification the default in network tools; `--insecure` is explicit.
- Fixed bounded OTP scheduling, JWT algorithm handling, ciphertext decoding, APK extraction limits, and manifest output.
- Added deterministic validation, unit tests, packaging checks, and GitHub Actions CI.
- Documented the optional `dsh-purge-safe` runtime used by `redteam_*` skills.
- Removed the machine-specific skill-directory fallback and included authorization templates in packages.
- Corrected project statistics and installation instructions.

## 3.1.0

- Previous public preset release.
