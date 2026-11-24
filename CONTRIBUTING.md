# Contributing

Thanks for taking a look! This project is intentionally **one file** — please keep it that way.

## Rules of the road

1. **No new runtime dependencies.** The engine must keep working with the Python standard library only.
   Optional accelerators (`cryptography`, `lxml`) are allowed *only* behind a `try/except ImportError` guard with a
   working stdlib fallback.
2. **One file.** Put engine changes inside the `#__PY_START__` … `#__PY_END__` block in `saml-hud.sh`.
3. **Never break the pipe contract.** Tokens must remain readable from stdin (`cat token | ./saml-hud.sh`); that is why
   the engine is extracted to a temp file instead of being fed through stdin.
4. **Report, don't guess.** If a check cannot be performed (no certificate, unsupported digest), say so explicitly —
   never print "Valid" on an unverified signature.

## Before you open a PR

```bash
bash -n saml-hud.sh
./tests/run_tests.sh
./saml-hud.sh --demo
./saml-hud.sh samples/signed_response.b64 -c samples/idp_cert.pem   # expect two "Valid Signature" rows
```

Add a sample to `samples/` and a case to `tests/run_tests.sh` for any new decoding path or audit rule.

## Commit style

`feat: …`, `fix: …`, `docs: …`, `test: …` — one logical change per commit.
