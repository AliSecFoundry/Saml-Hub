#!/usr/bin/env bash
# SAML HUD - dependency-free regression suite.
# Usage:  ./tests/run_tests.sh          (exit 0 = all pass)
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOL="$ROOT/saml-hud.sh"
S="$ROOT/samples"
PASS=0
FAIL=0

green() { printf '\033[38;5;46m%s\033[0m\n' "$1"; }
red()   { printf '\033[38;5;196m%s\033[0m\n' "$1"; }
dim()   { printf '\033[38;5;244m%s\033[0m\n' "$1"; }

check() { # check <name> <expected-rc> <command...>
    local name="$1" want="$2"; shift 2
    local out rc
    out="$("$@" 2>&1)"; rc=$?
    if [[ "$rc" == "$want" ]]; then
        green "  PASS  $name"; PASS=$((PASS+1))
    else
        red   "  FAIL  $name (rc=$rc, want $want)"
        printf '%s\n' "$out" | tail -5 | sed 's/^/        /'
        FAIL=$((FAIL+1))
    fi
}

expect() { # expect <name> <needle> <command...>
    local name="$1" needle="$2"; shift 2
    local out
    out="$("$@" 2>&1)"
    if grep -qF -- "$needle" <<<"$out"; then
        green "  PASS  $name"; PASS=$((PASS+1))
    else
        red   "  FAIL  $name (missing: $needle)"
        printf '%s\n' "$out" | tail -8 | sed 's/^/        /'
        FAIL=$((FAIL+1))
    fi
}

dim "SAML HUD test suite"
dim "tool: $TOOL"
echo

# ---------------------------------------------------------------- static checks
check "shell syntax"                        0 bash -n "$TOOL"
check "engine compiles (py_compile)"        0 bash -c \
    "sed -n '/^#__PY_START__\$/,/^#__PY_END__\$/p' '$TOOL' | sed '1d;\$d' > /tmp/.hud_engine_test.py && python3 -m py_compile /tmp/.hud_engine_test.py"
check "--help exits 0"                      0 "$TOOL" --help

# --------------------------------------------------------------- decode & verify
check "demo runs (rc 2 - it is unsigned by design)" 2 "$TOOL" --demo
check "verified token + pinned cert (rc 0)" 0 "$TOOL" "$S/signed_response.b64" -c "$S/idp_cert.pem"
expect "signature verified against pinned key" "Valid Signature (pinned key)" \
    "$TOOL" "$S/signed_response.b64" -c "$S/idp_cert.pem"
expect "NameID extracted"                   "elliot@kali-lab.local" \
    "$TOOL" "$S/signed_response.b64" -c "$S/idp_cert.pem"
expect "attributes rendered"                "SSOAdmin" \
    "$TOOL" "$S/signed_response.b64" -c "$S/idp_cert.pem"
expect "status is Successful"               "Successful" \
    "$TOOL" "$S/signed_response.b64"
expect "embedded cert used without --cert"  "Valid Signature (embedded key)" \
    "$TOOL" "$S/signed_response.b64"

check "stdin pipe"                          0 bash -c "cat '$S/signed_response.b64' | '$TOOL' -c '$S/idp_cert.pem'"
check "redirect URL signature (rc 0)"       0 "$TOOL" "$S/redirect_authn.url" -c "$S/sp_cert.pem"
expect "redirect query verified"             "Valid Signature" \
    "$TOOL" "$S/redirect_authn.url" -c "$S/sp_cert.pem"
expect "redirect binding detected"           "HTTP-Redirect" \
    "$TOOL" "$S/redirect_authn.url" -c "$S/sp_cert.pem"

check "burp capture (rc 0)"                 0 "$TOOL" "$S/burp_capture.http" -c "$S/idp_cert.pem"
expect "burp request detected"               "Raw HTTP request" \
    "$TOOL" "$S/burp_capture.http"
check "har hop 0 (rc 0)"                    0 "$TOOL" "$S/sso_trace.har"
check "har hop 1 (rc 0)"                    0 "$TOOL" "$S/sso_trace.har" --har-step 1
expect "har hop reported"                    "HAR capture (hop 1)" \
    "$TOOL" "$S/sso_trace.har" --har-step 1
check "encrypted assertion is reported"     0 bash -c \
    "'$TOOL' '$S/encrypted_response.xml' | grep -q 'EncryptedAssertion'"

# ------------------------------------------------------------------- tampering
expect "tampered assertion -> INVALID SIGNATURE" "INVALID SIGNATURE" \
    "$TOOL" "$S/tampered_response.b64" -c "$S/idp_cert.pem"
expect "tampered assertion -> SAML-002"          "SAML-002" \
    "$TOOL" "$S/tampered_response.b64" -c "$S/idp_cert.pem"
check "tampered assertion exits 2"              2 "$TOOL" "$S/tampered_response.b64" -c "$S/idp_cert.pem"
expect "wrong pinned cert is not accepted"      "INVALID SIGNATURE" \
    "$TOOL" "$S/signed_response.b64" -c "$S/sp_cert.pem"
expect "unsigned demo -> SAML-001"              "SAML-001" \
    "$TOOL" --demo

# ------------------------------------------------------------------ robustness
check "surrounding whitespace tolerated"    0 bash -c \
    "'$TOOL' \"   \$(cat '$S/signed_response.b64')   \" -c '$S/idp_cert.pem'"
check "url-encoded token tolerated"         0 bash -c \
    "'$TOOL' \"\$(python3 -c \"import urllib.parse,sys;print(urllib.parse.quote(open('$S/signed_response.b64').read()))\")\" -c '$S/idp_cert.pem'"
check "wrapped token (line breaks) decodes" 0 bash -c \
    "'$TOOL' \"\$(fold -w 64 '$S/signed_response.b64')\" -c '$S/idp_cert.pem'"

# ---------------------------------------------------------------- output modes
check "--json exits 0"                      0 "$TOOL" --json "$S/signed_response.b64"
check "--json is valid JSON"                0 bash -c "'$TOOL' --json '$S/signed_response.b64' | python3 -m json.tool >/dev/null"
check "--xml exits 0"                       0 bash -c "'$TOOL' --xml '$S/signed_response.b64' >/dev/null"
expect "--xml prints the XML"                "<samlp:Response" \
    "$TOOL" --xml "$S/signed_response.b64"
expect "--pem prints a certificate"          "BEGIN CERTIFICATE" \
    "$TOOL" "$S/signed_response.b64" -c "$S/idp_cert.pem" --pem
check "--no-color has no escapes"           0 bash -c \
    "! '$TOOL' --no-color '$S/signed_response.b64' | grep -q \$'\\033'"
check "unknown option exits 2"              2 "$TOOL" --nonsense
check "garbage input exits 3"               3 bash -c "echo 'not a saml message' | '$TOOL'"
expect "garbage input explains itself"       "Could not recognize this as SAML" \
    bash -c "echo 'not a saml message' | '$TOOL'"

# ------------------------------------------------------------------- summary
echo
if (( FAIL == 0 )); then
    green "ALL $PASS CHECKS PASSED"
    exit 0
else
    red "$FAIL FAILED / $((PASS+FAIL)) TOTAL"
    exit 1
fi
