# ⚡ SAML HUD

> A zero-install, single-file **SAML 2.0 inspector for the Kali Linux terminal**.
> Paste a `SAMLResponse`, a `SAMLRequest`, a redirect URL, raw XML, a Burp request or a `.har` capture — get a
> samltool.io-style dashboard with **real signature verification** and a **security audit** right in your shell.

```text
  ____    _    __  __ _        _   _ _   _ ____
 / ___|  / \  |  \/  | |      | | | | | | |  _ \
 \___ \ / _ \ | |\/| | |      | |_| | | | | | | |
  ___) / ___ \| |  | | |___   |  _  | |_| | |_| |
 |____/_/   \_\_|  |_|_____|  |_| |_|\___/|____/   v2.0
  :: SAML 2.0 decode . inspect . verify . audit        kali edition ::
```

![SAML HUD preview](docs/preview.svg)

---

## Why

`samltool.io` / `samltool.com` are great, but they are **cloud services**. During an engagement you often cannot
paste a customer's live SAMLResponse (session tokens, PII) into a third-party website, and lab boxes are frequently
offline. SAML HUD does the same job **locally, from your terminal**, with no install and no telemetry.

* **One file.** `saml-hud.sh` — bash entry point + embedded Python 3 engine (stdlib only).
* **No dependencies.** Works on a stock Kali install with just `python3`. If `lxml` / `cryptography` are present it
  uses them automatically for extra speed; otherwise its own pure-Python X.509 reader, exclusive-C14N canonicalizer
  and RSA verifier take over and produce identical results.
* **Nothing leaves the box.** No network calls. Ever.

---

## Install

```bash
git clone https://github.com/<you>/saml-hud.git
cd saml-hud
chmod +x saml-hud.sh

./saml-hud.sh --demo          # instant demo, no input needed
```

Optional — call it from anywhere as `saml-hud`:

```bash
sudo cp saml-hud.sh /usr/local/bin/saml-hud
# or, without sudo:
mkdir -p ~/.local/bin && cp saml-hud.sh ~/.local/bin/saml-hud    # ~/.local/bin is on PATH in Kali
```

---

## Usage

### Interactive paste mode
```bash
./saml-hud.sh
```
Paste anything (token, URL, XML, Burp request), then press **Ctrl-D** to analyze.

### From a file / URL / token
```bash
./saml-hud.sh samples/signed_response.b64 -c samples/idp_cert.pem
./saml-hud.sh 'https://idp.example.com/sso?SAMLRequest=fVJLa8JA...'
./saml-hud.sh samples/burp_capture.http -c samples/idp_cert.pem
./saml-hud.sh samples/sso_trace.har --har-step 1
```

### From a pipe
```bash
cat samples/signed_response.b64 | ./saml-hud.sh -c samples/idp_cert.pem
xclip -o -selection clipboard | ./saml-hud.sh
curl -s "$CAPTURE_URL" | ./saml-hud.sh
```

### Automation friendly
```bash
./saml-hud.sh token.b64 --json | jq '.findings'          # machine readable
./saml-hud.sh token.b64 --xml  > response.xml            # decoded XML only
./saml-hud.sh token.b64 --pem                            # dump the signing certificate
./saml-hud.sh token.b64 -c idp.pem; echo "exit=$?"        # 2 = CRITICAL/HIGH finding
```

### Options

| Flag | Meaning |
|---|---|
| `-c, --cert FILE` | Pinned IdP/SP certificate — PEM, bare Base64, **or** a metadata XML document |
| `-f, --file FILE` | Input file (same as the positional argument) |
| `-H, --har-step N` | Which SAML hop inside a `.har` capture to inspect (0-based) |
| `--json` | Machine-readable output (`jq` friendly) |
| `--xml` | Print only the decoded XML (pipe to `xmllint`, `grep`, a file) |
| `--pem` | Print the parsed signing certificate(s) as PEM after the report |
| `--color MODE` | Force colour depth: `truecolor`, `256`, `16`, `mono` |
| `--no-color` | Disable ANSI colours (also honours `NO_COLOR=1`) |
| `--demo` | Run against a built-in sample response |
| `-h, --help` | Usage screen |

**Exit codes:** `0` clean · `2` CRITICAL or HIGH finding · `3` input could not be decoded.

---

## What it accepts

Universal auto-detection, in this order:

| Input | Detection | Verified |
|---|---|---|
| `SAMLResponse` / `SAMLRequest` Base64 token | length + charset sniff | ✅ |
| Deflated Base64 (HTTP-Redirect payload) | raw-inflate (`wbits=-15`) | ✅ |
| Redirect URL with `?SAMLRequest=…&Signature=…` | URL parse + query signature | ✅ |
| Raw SAML XML / assertion | starts with `<` | ✅ |
| Copied **Burp Suite / ZAP** request (headers + form body) | `METHOD … HTTP/1.1` | ✅ |
| **`.har`** browser capture, multi-hop | `{"log": {"entries": …}}` | ✅ (`--har-step N`) |
| HTML auto-submit SSO form | `<form>` + `SAMLResponse` | ✅ |
| `application/x-www-form-urlencoded` body | form parse | ✅ |

---

## What it shows

Two-column dashboard, mirroring the familiar samltool layout:

* **COMMON** — Type, Version, Binding, Issuer, Destination, IssueInstant (+ “x minutes ago”), InResponseTo, RelayState
* **STATUS** — Successful / Requester / Responder, status codes, message
* **SIGNATURE** — `SAML Response` and `SAML Assertion` reported **separately**, plus the HTTP-Redirect query signature
* **CERTIFICATE** — Subject, Issuer, SerialNumber, Thumbprint (SHA-1), SHA-256, validity window, key size
* **ASSERTION** — NameID + format, Recipient, SubjectConfirmationData, SessionIndex, AuthnInstant, AuthnContext
* **CONDITIONS** — NotBefore, NotOnOrAfter, Audience, `ACTIVE` / `EXPIRED` / `NOT YET VALID`
* **ATTRIBUTES** — full claim URIs, FriendlyName, every value
* **SECURITY AUDIT** — severity-ranked findings (see below)

### Real cryptography, not decoration

1. Locate the `<ds:Reference URI>` that covers the element being checked.
2. Remove the enveloped `<ds:Signature>`, canonicalize (**exclusive C14N 1.0**, built in — byte-identical to lxml’s).
3. Compare the digest.
4. Canonicalize `<ds:SignedInfo>` and verify the **RSA PKCS#1 v1.5** signature in pure Python.
5. Report `Valid Signature (pinned key)` / `(embedded key)` / `INVALID SIGNATURE` and say **which** failed.

HTTP-Redirect signatures are checked over the **raw** percent-encoded query octets with the `Signature=` segment
removed, exactly as OASIS SAML Bindings §3.4.4.1 requires.

### Audit rules

| ID | Severity | Check |
|---|---|---|
| `SAML-001` | CRITICAL | Completely unsigned message |
| `SAML-002` | CRITICAL/HIGH | Broken digest, bad signature, or signer key ≠ pinned `--cert` |
| `SAML-003` | CRITICAL | `<!DOCTYPE` / `<!ENTITY` present (XXE / entity expansion) |
| `SAML-004` | CRITICAL | Multiple assertions / unresolvable Reference (XSW surface) |
| `SAML-005` | MEDIUM/LOW | Only Response signed, or only Assertion signed |
| `SAML-006` | HIGH | SHA-1 / MD5 signature or digest |
| `SAML-007` | HIGH | Expired / not-yet-valid / weak (<2048-bit) signing certificate |
| `SAML-009` | HIGH | XML comments in the document (CVE-2017-11427 truncation pattern) |
| `SAML-010` | HIGH/MEDIUM | Missing `<Conditions>`, or lifetime > 60 min |
| `SAML-011` | HIGH | Assertion expired / future `NotBefore` |
| `SAML-012` | HIGH | Missing `<AudienceRestriction>` |
| `SAML-014` | LOW | Unsolicited (IdP-initiated) response — no `InResponseTo` |
| `SAML-015` | HIGH/MEDIUM | EncryptedAssertion needs decrypting · plaintext `http://` endpoint |

---

## Examples

```bash
# good token, pinned cert -> two green rows, audit clean
$ ./saml-hud.sh samples/signed_response.b64 -c samples/idp_cert.pem
│ SAML Response         Valid Signature (pinned key)│
│ SAML Assertion        Valid Signature (pinned key)│

# tampered NameID -> digest fails, CRITICAL finding, exit 2
$ ./saml-hud.sh samples/tampered.b64 -c samples/idp_cert.pem
│ SAML Assertion                   INVALID SIGNATURE│
┃ ✖ CRITICAL SAML-002  SAML Assertion signature failed verification: digest mismatch …
```

---

## Terminal requirements

* A UTF-8 locale (Kali default) for the box drawing.
* 256-colour terminal for the full neon theme; automatic fallback to 16 colours, or `--no-color` / `NO_COLOR=1`.
  Truecolor is used automatically when `COLORTERM=truecolor`. The footer always reports the active depth.
* `python3` (3.8+). Nothing else.

---

## Development

```bash
bash -n saml-hud.sh                 # shell syntax
./tests/run_tests.sh                # smoke + regression suite (pytest-free)
```

The Python engine is delimited by `#__PY_START__` / `#__PY_END__` inside the file; it is extracted to a temp file at
run time so that stdin stays free for piped tokens.

## Legal

For **authorised** security testing, debugging your own SSO integrations, and education only. The samples included
are synthetic. Do not use it against systems you do not own or have written permission to test.

## License

MIT — see [LICENSE](LICENSE).
