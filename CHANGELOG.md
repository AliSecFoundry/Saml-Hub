# Changelog

All notable changes to SAML HUD are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning is [SemVer](https://semver.org/).

## [2.0] — 2026-11-24

### Added
- Single-file `saml-hud.sh` (bash entry point + embedded stdlib-only Python 3 engine).
- Universal 8-format input auto-detection: Base64, Deflate+Base64, redirect URL, raw XML, Burp/ZAP HTTP capture,
  `.har` browser capture (multi-hop, `--har-step`), HTML auto-submit form, urlencoded body.
- samltool-style two-column dashboard: Common, Status, Signature, Certificate, Assertion, Conditions, Attributes.
- **Real XMLDSig verification**: enveloped-signature removal, built-in exclusive C14N 1.0 canonicalizer
  (byte-identical to lxml), digest comparison, pure-Python RSA PKCS#1 v1.5 signature math.
- **HTTP-Redirect binding signature verification** over the raw query string (SAML Bindings §3.4.4.1).
- X.509 parsing with a hand-rolled DER reader when `cryptography` is unavailable (subject, issuer, serial,
  validity, RSA key size, SHA-1/SHA-256 fingerprints).
- `--cert` accepts PEM, bare Base64, or IdP **metadata XML**; mismatched signer keys are reported.
- Security auditor with severity-ranked findings (`SAML-001` … `SAML-015`).
- Output modes: dashboard, `--json` (jq friendly), `--xml`, `--pem`, `--no-color`.
- Colour-depth detection (truecolor / 256 / 16 / mono) with `--color` override; footer reports the active depth.
- Exit codes: `0` clean, `2` CRITICAL/HIGH finding, `3` undecodable input.
- Sample corpus (`samples/`) and dependency-free regression suite (`tests/run_tests.sh`).

### Fixed
- Piped input no longer consumed by the interpreter: the engine is extracted to a temp file so stdin stays free.
- Broken pipe (`| head`) exits cleanly instead of printing a `BrokenPipeError` traceback.
- Signed-element selection now resolves the `<ds:Reference URI>` that actually points at the element under test
  (avoids verifying a sibling signature — a common false-negative in XSW cases).
- Certificate DN parsing handles multi-valued RDNs and UTF-8 values.

## [1.0]
- Internal prototype.

[2.0]: https://github.com/<you>/saml-hud/releases/tag/v2.0
