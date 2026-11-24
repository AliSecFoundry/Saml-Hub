#!/usr/bin/env bash
# =====================================================================================
#  ██████  █████  ███    ███ ██      ██   ██     ██   ██ ██    ██ ██████
#  ██      ██  ██ ████  ████ ██       ██ ██      ██   ██ ██    ██ ██   ██
#  ███████ ██████ ██ ████ ██ ██        ███       ███████ ██    ██ ██   ██
#       ██ ██  ██ ██  ██  ██ ██       ██ ██      ██   ██ ██    ██ ██   ██
#  ███████ ██  ██ ██      ██ ███████ ██   ██     ██   ██  ██████  ██████
#
#  SAML HUD  ::  zero-install SAML 2.0 terminal inspector for Kali Linux
#  Paste a SAMLResponse, SAMLRequest, redirect URL, raw XML, Burp request or HAR.
#  Single file. Pure bash + embedded Python 3 (standard library only).
#
#  Usage:   ./saml-hud.sh                      # interactive paste mode (Ctrl-D to submit)
#           ./saml-hud.sh token.b64            # file / URL / capture
#           cat capture.http | ./saml-hud.sh   # stdin pipe
#           ./saml-hud.sh --cert idp.pem -f token.b64
#           ./saml-hud.sh --json -f token.b64  # machine readable
#           ./saml-hud.sh --demo               # built-in demo response
# =====================================================================================

set -o pipefail

SELF="${BASH_SOURCE[0]}"
PY="${SAML_HUD_PYTHON:-python3}"

if ! command -v "$PY" >/dev/null 2>&1; then
    printf '\033[38;5;196m[!] python3 not found. Install it:  sudo apt install -y python3\033[0m\n' >&2
    exit 127
fi

# The Python engine is embedded below so this stays a single deliverable file.
# It is extracted to a temp file (not fed through stdin) so SAML tokens can still be piped in.
PY_SRC="$(mktemp "${TMPDIR:-/tmp}/saml-hud.XXXXXX.py")" || exit 1
trap 'rm -f "$PY_SRC"' EXIT INT TERM
sed -n '/^#__PY_START__$/,/^#__PY_END__$/p' "$SELF" | sed '1d;$d' > "$PY_SRC"
if [ ! -s "$PY_SRC" ]; then
    printf '\033[38;5;196m[!] could not extract the SAML HUD engine from %s\033[0m\n' "$SELF" >&2
    exit 1
fi
"$PY" "$PY_SRC" "$@"
exit $?

# never executed by bash - only used as a parse-safe container for the engine
: <<'SAML_HUD_PY_BODY'
#__PY_START__
# -*- coding: utf-8 -*-
"""SAML HUD - cyber-themed SAML 2.0 inspector (stdlib only, optional samlx boost)."""

from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import json
import os
import re
import sys
import textwrap
import time
import urllib.parse
import zlib
from datetime import datetime, timezone
from xml.etree import ElementTree as ET
from xml.dom import expatbuilder  # namespace-aware DOM used by the C14N helpers

VERSION = "2.0"
TOOL = "SAML HUD"

# ----------------------------------------------------------------------------- style
def _detect_color_mode() -> str:
    """truecolor | 256 | 16 | none - matches what the terminal really supports."""
    if os.environ.get("NO_COLOR") is not None:
        return "none"
    if os.environ.get("SAML_HUD_COLOR"):           # manual override, e.g. SAML_HUD_COLOR=16
        mode = os.environ["SAML_HUD_COLOR"].lower()
        return {"truecolor": "truecolor", "24bit": "truecolor", "256": "256",
                "16": "16", "mono": "none", "none": "none"}.get(mode, "256")
    if not sys.stdout.isatty() and not os.environ.get("FORCE_COLOR"):
        return "none"
    colorterm = os.environ.get("COLORTERM", "").lower()
    if colorterm in ("truecolor", "24bit"):
        return "truecolor"
    term = os.environ.get("TERM", "").lower()
    if "256color" in term or term.startswith(("xterm", "alacritty", "kitty", "wezterm")):
        return "256"
    if term in ("", "dumb"):
        return "none"
    return "16"


COLOR_MODE = _detect_color_mode()

# name -> (256-colour index, nearest 16-colour SGR foreground, 24-bit hex)
_PALETTE = {
    "CYAN":  (51,  "96", "#33e1ed"),   # bright cyan
    "ICE":   (45,  "96", "#2ee6c5"),   # cyan / turquoise
    "BLUE":  (39,  "94", "#3aa0ff"),   # bright blue
    "MAG":   (201, "95", "#ff41d6"),   # magenta
    "PURP":  (141, "95", "#b08cff"),   # violet
    "GREEN": (46,  "92", "#2bff88"),   # bright green
    "LIME":  (118, "92", "#a8ff3e"),   # lime
    "AMBER": (214, "93", "#ffb340"),   # amber / yellow
    "RED":   (196, "91", "#ff3b4e"),   # bright red
    "ROSE":  (203, "91", "#ff7a8a"),   # salmon
    "GREY":  (244, "90", "#8b93a7"),   # grey
    "WHITE": (255, "97", "#e7ecf5"),   # near-white
    "DARK":  (238, "90", "#3a4152"),
}


def _fg(name: str) -> str:
    idx, ansi16, hexv = _PALETTE[name]
    if COLOR_MODE == "truecolor":
        r, g, b = (int(hexv[i:i + 2], 16) for i in (1, 3, 5))
        return f"\033[38;2;{r};{g};{b}m"
    if COLOR_MODE == "16":
        return f"\033[{ansi16}m"
    return f"\033[38;5;{idx}m"


class C:
    R = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    CYAN = _fg("CYAN")
    ICE = _fg("ICE")
    BLUE = _fg("BLUE")
    MAG = _fg("MAG")
    PURP = _fg("PURP")
    GREEN = _fg("GREEN")
    LIME = _fg("LIME")
    AMBER = _fg("AMBER")
    RED = _fg("RED")
    ROSE = _fg("ROSE")
    GREY = _fg("GREY")
    WHITE = _fg("WHITE")
    DARK = _fg("DARK")


ENABLED = COLOR_MODE != "none"


def apply_theme() -> None:
    """Rebuild the C class from the active COLOR_MODE (called at start and after --color)."""
    global C
    attrs = {"R": "\033[0m", "BOLD": "\033[1m", "DIM": "\033[2m"}
    attrs.update({name: _fg(name) for name in _PALETTE})
    C = type("C", (), attrs)


def col(c: str) -> str:
    return c if ENABLED else ""


def w(s: str) -> str:
    """Visible width of a string (ignores ANSI escapes)."""
    return len(re.sub(r"\033\[[0-9;]*m", "", s))


def pad(s: str, width: int, align: str = "left") -> str:
    gap = max(0, width - w(s))
    if align == "right":
        return " " * gap + s
    if align == "center":
        left = gap // 2
        return " " * left + s + " " * (gap - left)
    return s + " " * gap


def clip(s: str, width: int) -> str:
    """Truncate to visible width, adding an ellipsis, ANSI-safe for plain strings."""
    plain = s
    if w(plain) <= width:
        return s
    return plain[: max(0, width - 1)] + "…"


# ------------------------------------------------------------------------- semantics
NS = {
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
    "xenc": "http://www.w3.org/2001/04/xmlenc#",
    "md": "urn:oasis:names:tc:SAML:2.0:metadata",
}

STATUS_NAMES = {
    "urn:oasis:names:tc:SAML:2.0:status:Success": "Successful",
    "urn:oasis:names:tc:SAML:2.0:status:Requester": "Requester Error",
    "urn:oasis:names:tc:SAML:2.0:status:Responder": "Responder Error",
    "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch": "Version Mismatch",
}


def local(tag: str) -> str:
    return tag.split("}", 1)[1] if "}" in tag else tag


def ns_of(tag: str) -> str:
    return tag[1:].split("}", 1)[0] if tag.startswith("{") else ""


def child(el, *names):
    for c in el:
        if local(c.tag) in names:
            return c
    return None


def children(el, *names):
    return [c for c in el.iter() if local(c.tag) in names]


def txt(el) -> str:
    return "".join(el.itertext()).strip() if el is not None else ""


# -------------------------------------------------------------------- DER / cert ops
class Der:
    """Tiny ASN.1 DER reader - just enough to pull a cert's public fields."""

    def __init__(self, data: bytes, pos: int = 0):
        self.d = data
        self.p = pos

    def tlv(self):
        d, p = self.d, self.p
        tag = d[p]
        p += 1
        ln = d[p]
        p += 1
        if ln & 0x80:
            n = ln & 0x7F
            ln = int.from_bytes(d[p:p + n], "big")
            p += n
        val = d[p:p + ln]
        self.p = p + ln
        return tag, val

    def seq(self):
        tag, val = self.tlv()
        return Der(val, 0)


def oid_str(b: bytes) -> str:
    if not b:
        return ""
    parts = [b[0] // 40, b[0] % 40]
    n = 0
    for byte in b[1:]:
        n = (n << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(n)
            n = 0
    return ".".join(str(x) for x in parts)


OID_NAMES = {
    "2.5.4.3": "CN",
    "2.5.4.6": "C",
    "2.5.4.7": "L",
    "2.5.4.8": "ST",
    "2.5.4.10": "O",
    "2.5.4.11": "OU",
    "1.2.840.113549.1.9.1": "E",
    "0.9.2342.19200300.100.1.25": "DC",
    "2.5.4.5": "serialNumber",
    "1.2.840.113549.1.1.1": "RSA",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.10045.2.1": "EC",
}


def parse_name(der: Der) -> str:
    """RDNSequence content -> 'CN=x, O=y, C=z'."""
    out = []
    seq = Der(der.d, der.p)
    while seq.p < len(seq.d):
        try:
            _, rdn = seq.tlv()                 # SET OF AttributeTypeAndValue
        except IndexError:
            break
        rdn_reader = Der(rdn, 0)
        while rdn_reader.p < len(rdn_reader.d):
            try:
                _, atv = rdn_reader.tlv()      # SEQUENCE { type, value }
                a = Der(atv, 0)
                _, oidv = a.tlv()
                _, valv = a.tlv()
            except IndexError:
                break
            name = OID_NAMES.get(oid_str(oidv), oid_str(oidv))
            out.append(f"{name}={valv.decode('utf-8', 'replace')}")
    return ", ".join(out)


def parse_time(tag: int, val: bytes) -> datetime | None:
    raw = val.decode("ascii", "replace").rstrip("Z")
    try:
        if tag == 0x17:  # UTCTime YYMMDDHHMMSS
            yy = int(raw[0:2])
            year = 2000 + yy if yy < 50 else 1900 + yy
            rest = raw[2:]
            return datetime(int(year), int(rest[0:2]), int(rest[2:4]), int(rest[4:6]),
                            int(rest[6:8]), int(rest[8:10] or 0), tzinfo=timezone.utc)
        return datetime(int(raw[0:4]), int(raw[4:6]), int(raw[6:8]), int(raw[8:10]),
                        int(raw[10:12]), int(raw[12:14]), tzinfo=timezone.utc)
    except Exception:
        return None


def cert_info(b64_or_pem: str) -> dict | None:
    """Parse an X.509 cert using cryptography if present, else the mini DER reader."""
    raw = re.sub(r"-----[^-]+-----", "", b64_or_pem)
    raw = re.sub(r"\s+", "", raw)
    try:
        der = base64.b64decode(raw + "=" * (-len(raw) % 4), validate=False)
    except (binascii.Error, ValueError):
        return None

    info = {
        "pem": "-----BEGIN CERTIFICATE-----\n" + "\n".join(textwrap.wrap(raw, 64))
        + "\n-----END CERTIFICATE-----",
        "sha256": ":".join(f"{b:02X}" for b in hashlib.sha256(der).digest()),
        "sha1": ":".join(f"{b:02X}" for b in hashlib.sha1(der).digest()),
        "der": der,
    }

    try:  # rich path
        from cryptography import x509  # type: ignore
        from cryptography.hazmat.primitives import hashes  # type: ignore
        from cryptography.hazmat.primitives.asymmetric import ec, rsa  # type: ignore

        c = x509.load_der_x509_certificate(der)
        info["subject"] = c.subject.rfc4514_string()
        info["issuer"] = c.issuer.rfc4514_string()
        info["serial"] = format(c.serial_number, "x")
        info["not_before"] = c.not_valid_before_utc
        info["not_after"] = c.not_valid_after_utc
        info["sha256"] = ":".join(f"{b:02X}" for b in c.fingerprint(hashes.SHA256()))
        info["sha1"] = ":".join(f"{b:02X}" for b in c.fingerprint(hashes.SHA1()))
        info["self_signed"] = c.subject == c.issuer
        pub = c.public_key()
        if isinstance(pub, rsa.RSAPublicKey):
            info["key"] = f"RSA {pub.key_size}"
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            info["key"] = f"EC {pub.curve.name} {pub.key_size}"
        else:
            info["key"] = type(pub).__name__
        info["rsa_pub"] = ((lambda n: (n.n, n.e))(pub.public_numbers())
                           if isinstance(pub, rsa.RSAPublicKey) else None)
        return info
    except Exception:
        pass

    # fallback: hand-rolled DER walk
    try:
        outer = Der(der).seq()          # Certificate
        tbs = outer.seq()               # TBSCertificate
        tag, _ = tbs.tlv()              # [0] version (optional)
        if tag != 0xA0:
            tbs.p = 0
            tbs.tlv()                   # re-read serial as first element
        tag, serial = tbs.tlv()         # serialNumber
        info["serial"] = format(int.from_bytes(serial, "big"), "x")
        tbs.tlv()                       # signature AlgorithmIdentifier
        tag, issuer_val = tbs.tlv()     # issuer
        info["issuer"] = parse_name(Der(issuer_val, 0))
        tag, validity = tbs.tlv()       # validity
        v = Der(validity, 0)
        nt, nv = v.tlv()
        at, av = v.tlv()
        info["not_before"] = parse_time(nt, nv)
        info["not_after"] = parse_time(at, av)
        tag, subj_val = tbs.tlv()
        info["subject"] = parse_name(Der(subj_val, 0))
        info["self_signed"] = info["subject"] == info["issuer"]
        info["key"] = "RSA/EC"
        info["rsa_pub"] = _spki_rsa(tbs)
    except Exception:
        return None
    return info


def _spki_rsa(tbs: Der):
    """Pull RSA (n, e) out of SubjectPublicKeyInfo, if it is RSA."""
    try:
        tag, spki = tbs.tlv()           # subjectPublicKeyInfo
        s = Der(spki, 0)
        tag, alg = s.tlv()
        a = Der(alg, 0)
        _, oidv = a.tlv()
        if oid_str(oidv) != "1.2.840.113549.1.1.1":
            return None
        tag, bits = s.tlv()
        key = Der(bits[1:], 0).seq()
        _, nv = key.tlv()
        _, ev = key.tlv()
        return (int.from_bytes(nv, "big"), int.from_bytes(ev, "big"))
    except Exception:
        return None


# ----------------------------------------------------- pure-python RSA (redirect sigs)
DIGEST_INFO = {
    "sha1": (hashlib.sha1, bytes.fromhex("3021300906052b0e03021a05000414")),
    "sha256": (hashlib.sha256, bytes.fromhex("3031300d060960864801650304020105000420")),
    "sha384": (hashlib.sha384, bytes.fromhex("3041300d060960864801650304020205000430")),
    "sha512": (hashlib.sha512, bytes.fromhex("3051300d060960864801650304020305000440")),
}


def rsa_pkcs1_verify(pub, message: bytes, signature: bytes, digest: str) -> bool:
    if pub is None or digest not in DIGEST_INFO:
        return False
    if not isinstance(pub, (tuple, list)):
        nums = pub.public_numbers() if hasattr(pub, "public_numbers") else pub
        pub = (nums.n, nums.e)
    n, e = pub
    k = (n.bit_length() + 7) // 8
    if len(signature) != k:
        return False
    m = pow(int.from_bytes(signature, "big"), e, n)
    em = m.to_bytes(k, "big")
    hasher, prefix = DIGEST_INFO[digest]
    expected = prefix + hasher(message).digest()
    tail = b"\x00" + expected
    if not em.startswith(b"\x00\x01"):
        return False
    idx = em.find(b"\x00", 2)
    if idx < 0:
        return False
    padding = em[2:idx]
    if len(padding) < 8 or padding != b"\xff" * len(padding):
        return False
    return em[idx:] == tail


def _md_inscope(el) -> dict:
    ns, chain = {}, []
    cur = el.parentNode          # bindings inherited from ancestors only
    while cur is not None and getattr(cur, "nodeType", None) == 1:
        chain.append(cur)
        cur = cur.parentNode
    for node in reversed(chain):
        for i in range(node.attributes.length):
            a = node.attributes.item(i)
            if a.name == "xmlns":
                ns[""] = a.value
            elif a.name.startswith("xmlns:"):
                ns[a.name[6:]] = a.value
    return ns


def _md_attr_escape(v: str) -> str:
    return (v.replace("&", "&amp;").replace("<", "&lt;").replace('"', "&quot;")
             .replace("\t", "&#x9;").replace("\n", "&#xA;").replace("\r", "&#xD;"))


def _md_text_escape(t: str) -> str:
    return t.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\r", "&#xD;")


def _md_walk(el, rendered, out, exclusive, with_comments, top):
    pfx = el.prefix or ""
    uri = el.namespaceURI or ""
    name_local = el.localName or el.nodeName
    rendered = dict(rendered)
    decls = []
    if uri and (top or rendered.get(pfx) != uri):
        # apex of the canonicalized subtree always re-declares its own namespace
        decls.append((pfx, uri))
        rendered[pfx] = uri
    attrs = []
    for i in range(el.attributes.length):
        a = el.attributes.item(i)
        if a.name == "xmlns" or a.name.startswith("xmlns:"):
            if not exclusive:
                p = a.name[6:]
                rendered[p] = a.value
                decls.append((p, a.value))
            continue
        ans = a.namespaceURI or ""
        ap = a.prefix or ""
        alocal = a.localName or a.name
        if ans and rendered.get(ap) != ans and (ap, ans) not in decls:
            decls.append((ap, ans))
            rendered[ap] = ans
        attrs.append(((ans, alocal), (ap + ":" + alocal) if ap else alocal, a.value))
    attrs.sort(key=lambda t: t[0])
    qname = f"{pfx}:{name_local}" if pfx else name_local
    out.append("<" + qname)
    for pp, uu in decls:
        out.append(f' xmlns{":" + pp if pp else ""}="{_md_attr_escape(uu)}"')
    for _, an, av in attrs:
        out.append(f' {an}="{_md_attr_escape(av)}"')
    out.append(">")
    for node in el.childNodes:
        t = node.nodeType
        if t in (node.TEXT_NODE, node.CDATA_SECTION_NODE):
            out.append(_md_text_escape(node.data))
        elif t == node.ELEMENT_NODE:
            _md_walk(node, rendered, out, exclusive, with_comments, False)
        elif t == node.COMMENT_NODE and with_comments:
            out.append(f"<!--{node.data}-->")
    out.append(f"</{qname}>")


def c14n_minidom(el, exclusive: bool = True, with_comments: bool = False) -> bytes:
    """Exclusive/Inclusive XML C14N 1.0 using only the standard library."""
    out: list[str] = []
    _md_walk(el, _md_inscope(el) if exclusive else {}, out, exclusive, with_comments, True)
    return "".join(out).encode("utf-8")


def _verify_with_minidom(xml_text: str, signed_id: str, sig_params: dict, pub) -> tuple[bool | None, str]:
    try:
        dom = expatbuilder.ExpatBuilderNS().parseString(xml_text)
    except Exception as exc:
        return None, f"XML reparse failed: {exc}"
    root = dom.documentElement

    def by_id(doc, ident):
        for el in doc.getElementsByTagName("*"):
            if not ident:
                if el is root:
                    return el
                continue
            if ident in (el.getAttribute("ID"), el.getAttribute("Id"), el.getAttribute("id")):
                return el
        return None

    # locate the <ds:Signature> whose Reference URI covers `signed_id`
    chosen = None
    for sig in root.getElementsByTagNameNS(NS["ds"], "Signature"):
        for ref in sig.getElementsByTagNameNS(NS["ds"], "Reference"):
            if ref.getAttribute("URI").lstrip("#") == signed_id:
                chosen = sig
                break
        if chosen is not None:
            break
    if chosen is None:
        sigs = root.getElementsByTagNameNS(NS["ds"], "Signature")
        chosen = sigs[0] if sigs else None

    if signed_id and by_id(dom, signed_id) is None:
        # signed_id may be stale/removed - fall back to the Reference that does resolve
        for sig in root.getElementsByTagNameNS(NS["ds"], "Signature"):
            for ref in sig.getElementsByTagNameNS(NS["ds"], "Reference"):
                uri = ref.getAttribute("URI").lstrip("#")
                if uri and by_id(dom, uri) is not None:
                    signed_id, chosen = uri, sig
                    break
            if chosen is not None and signed_id and by_id(dom, signed_id) is not None:
                break

    target = by_id(dom, signed_id)
    if target is None:
        return None, f"Reference URI {signed_id or '(document)'} does not resolve to an element (XSW indicator)"

    exclusive = "exc-c14n" in (sig_params.get("CanonicalizationMethod") or "")
    with_comments = "WithComments" in (sig_params.get("CanonicalizationMethod") or "")

    import copy as _copy
    tcopy = _copy.deepcopy(target)
    for child in list(tcopy.childNodes):
        if child.nodeType == 1 and (child.localName or "") == "Signature":
            tcopy.removeChild(child)
    canonical = c14n_minidom(tcopy, exclusive, with_comments)

    digest_name = (sig_params.get("DigestMethod") or "sha256").lower().replace("-", "")
    hasher = {"sha1": hashlib.sha1, "sha256": hashlib.sha256,
              "sha384": hashlib.sha384, "sha512": hashlib.sha512}.get(digest_name)
    if hasher is None:
        return None, f"unsupported digest {digest_name}"
    if base64.b64encode(hasher(canonical).digest()).decode().strip() != \
            (sig_params.get("DigestValue") or "").strip():
        return False, "digest mismatch - signed content was modified after signing"

    if pub is None:
        return None, "no RSA public key available"
    si = chosen.getElementsByTagNameNS(NS["ds"], "SignedInfo")
    if not si:
        return None, "SignedInfo not found"
    si_c14n = sig_params.get("CanonicalizationMethod") or "xml-exc-c14n"
    si_bytes = c14n_minidom(si[0], "exc-c14n" in si_c14n, "WithComments" in si_c14n)

    sig_name = (sig_params.get("SignatureMethod") or "sha256").lower()
    digest_for_sig = ("sha1" if "sha1" in sig_name else "sha384" if "sha384" in sig_name
                      else "sha512" if "sha512" in sig_name else "sha256")
    sv = chosen.getElementsByTagNameNS(NS["ds"], "SignatureValue")
    sv_text = "".join(c.data for c in sv[0].childNodes) if sv else ""
    try:
        raw_sig = base64.b64decode(sv_text.strip() + "===")
    except (binascii.Error, ValueError):
        return False, "SignatureValue is not valid Base64"
    if rsa_pkcs1_verify(pub, si_bytes, raw_sig, digest_for_sig):
        return True, "digest + RSA signature verified (stdlib canonicalizer)"
    return False, "RSA signature does not match SignedInfo (bad key or tampering)"


def verify_xml_signature(xml_text: str, signed_id: str, sig_params: dict, pub) -> tuple[bool | None, str]:
    """Verify an enveloped XMLDSig (Reference -> digest, SignedInfo -> RSA) with lxml.

    Returns (result, detail). result is None when the local parser cannot canonicalize.
    """
    if pub is None:
        return None, "no RSA public key available"
    try:
        from lxml import etree  # native C14N if lxml happens to be installed
    except Exception:
        return _verify_with_minidom(xml_text, signed_id, sig_params, pub)
    try:
        root = etree.fromstring(xml_text.encode("utf-8"), etree.XMLParser(
            resolve_entities=False, no_network=True, huge_tree=True))
    except etree.XMLSyntaxError as exc:
        return None, f"XML reparse failed: {exc}"

    target = None
    for el in root.iter():
        if el.get("ID") == signed_id or el.get("Id") == signed_id or el.get("id") == signed_id:
            target = el
            break
        for attr_val in (el.attrib or {}).values():
            if attr_val == signed_id and signed_id:
                target = el
                break
        if target is not None:
            break
    if target is None:
        return None, f"Reference URI {signed_id or '(empty)'} does not resolve to an element (XSW indicator)"

    exclusive = "exc-c14n" in (sig_params.get("CanonicalizationMethod") or "")
    with_comments = "WithComments" in (sig_params.get("CanonicalizationMethod") or "")
    # Enveloped signature: the covering <ds:Signature> element is NOT part of the digest
    signed_copy = copy.deepcopy(target)
    for dsig in [c for c in signed_copy if local(c.tag) == "Signature"]:
        signed_copy.remove(dsig)
    try:
        canonical = etree.tostring(signed_copy, method="c14n", exclusive=exclusive,
                                   with_comments=with_comments)
    except Exception as exc:
        return None, f"canonicalization failed: {exc}"

    digest_name = (sig_params.get("DigestMethod") or "sha256").lower().replace("-", "")
    hasher = {"sha1": hashlib.sha1, "sha256": hashlib.sha256,
              "sha384": hashlib.sha384, "sha512": hashlib.sha512}.get(digest_name)
    if hasher is None:
        return None, f"unsupported digest {digest_name}"
    got = base64.b64encode(hasher(canonical).digest()).decode()
    if got.strip() != (sig_params.get("DigestValue") or "").strip():
        return False, "digest mismatch - signed content was modified after signing"

    si_c14n = (sig_params.get("SignedInfoC14N") or sig_params.get("CanonicalizationMethod")
               or "http://www.w3.org/2001/10/xml-exc-c14n#")
    # pick the <ds:Signature> whose <Reference URI> points at the element we just digested
    si_el = None
    chosen_sig = None
    for cand in [el for el in root.iter() if local(el.tag) == "Signature"]:
        for ref in cand.iter():
            if local(ref.tag) == "Reference" and ref.get("URI", "").lstrip("#") == signed_id:
                chosen_sig = cand
                break
        if chosen_sig is not None:
            break

    def first_text(node, name):
        for c in node.iter():
            if local(c.tag) == name and (c.text or "").strip():
                return (c.text or "").strip()
        return ""

    if chosen_sig is not None:
        sig_params = dict(sig_params)
        sig_params["SignatureValue"] = first_text(chosen_sig, "SignatureValue")
        for el in chosen_sig:
            if local(el.tag) == "SignedInfo":
                si_el = el
                break
    if si_el is None:
        for el in root.iter():
            if local(el.tag) == "SignedInfo":
                si_el = el
                break
    if si_el is None:
        return None, "SignedInfo not found"
    try:
        si_bytes = etree.tostring(si_el, method="c14n", exclusive="exc-c14n" in si_c14n,
                                  with_comments="WithComments" in si_c14n)
    except Exception as exc:
        return None, f"SignedInfo canonicalization failed: {exc}"

    sig_name = (sig_params.get("SignatureMethod") or "sha256").lower()
    digest_for_sig = "sha1" if "sha1" in sig_name else "sha384" if "sha384" in sig_name \
        else "sha512" if "sha512" in sig_name else "sha256"
    try:
        raw_sig = base64.b64decode((sig_params.get("SignatureValue") or "") + "===")
    except (binascii.Error, ValueError):
        return False, "SignatureValue is not valid Base64"
    if rsa_pkcs1_verify(pub, si_bytes, raw_sig, digest_for_sig):
        return True, "digest + RSA signature verified"
    return False, "RSA signature does not match SignedInfo (bad key or tampering)"


# ------------------------------------------------------------------------- decoding
RAW_HTTP_START = re.compile(r"^(GET|POST|PUT|PATCH|DELETE)\s+\S+\s+HTTP/", re.I)


def b64_decode(token: str) -> bytes | None:
    s = re.sub(r"\s+", "", token)
    s = s.replace("-", "+").replace("_", "/")
    s = urllib.parse.unquote(s)
    s += "=" * (-len(s) % 4)
    try:
        return base64.b64decode(s, validate=False)
    except (binascii.Error, ValueError):
        return None


def inflate(data: bytes) -> bytes | None:
    for func in (lambda d: zlib.decompress(d, -15), zlib.decompress, lambda d: zlib.decompress(d, 47)):
        try:
            out = func(data)
            if out:
                return out
        except Exception:
            continue
    return None


def looks_xml(data: bytes) -> bool:
    head = data.lstrip()[:200]
    return head.startswith(b"<") or head.startswith(b"\xef\xbb\xbf<")


class Payload:
    def __init__(self):
        self.xml = ""
        self.kind = ""
        self.binding = ""
        self.params: dict[str, str] = {}
        self.relay_state: str | None = None
        self.raw_size = 0
        self.chain: list[str] = []
        self.error: str | None = None
        self.har_steps: list[dict] = []
        self.redirect_sig: dict | None = None
        self.note: str = ""
        self.pinned_pubs: list = []
        self.embedded_pubs: list = []


def token_to_xml(tok: str, payload: Payload) -> str | None:
    data = b64_decode(tok)
    if data is None:
        return None
    payload.chain.append("Base64")
    if data[:1] == b"\x78" or not looks_xml(data):
        inflated = inflate(data)
        if inflated:
            payload.chain.append("Raw-Deflate")
            data = inflated
    if data[:2] == b"\x1f\x8b":
        inflated = inflate(data)
        if inflated:
            payload.chain.append("GZIP")
            data = inflated
    if not looks_xml(data):
        return None
    return data.decode("utf-8", "replace")


def decode_input(raw: str, har_step: int | None = None) -> Payload:
    p = Payload()
    p.raw_size = len(raw.encode("utf-8", "replace"))
    text = raw.strip()
    if not text:
        p.error = "No input received."
        return p

    # ---- HAR capture
    if text.startswith("{") and '"log"' in text[:4000]:
        try:
            har = json.loads(text)
            entries = har.get("log", {}).get("entries", [])
            for i, e in enumerate(entries):
                req, resp = e.get("request", {}), e.get("response", {})
                url = req.get("url", "")
                q = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
                post = req.get("postData") or {}
                body = post.get("text", "") or urllib.parse.urlencode(
                    {pr.get("name", ""): pr.get("value", "") for pr in post.get("params", []) or []})
                content = (resp.get("content") or {}).get("text", "") or ""
                blob = body + content + url
                if "SAMLResponse" in blob or "SAMLRequest" in blob or "<saml" in blob.lower():
                    p.har_steps.append({
                        "index": i,
                        "method": req.get("method", ""),
                        "url": url,
                        "status": resp.get("status", ""),
                        "body": body,
                        "content": content,
                        "params": {k: v[0] for k, v in q.items()},
                        "time": e.get("time"),
                    })
            if not p.har_steps:
                p.error = "HAR parsed, but no SAML flows found inside it."
                return p
            idx = har_step or 0
            step = p.har_steps[idx] if 0 <= idx < len(p.har_steps) else None
            if step is None:
                p.error = f"--har-step {har_step} out of range (0-{len(p.har_steps) - 1})."
                return p
            p.kind = f"HAR capture (hop {step['index']})"
            if len(p.har_steps) > 1:
                others = ", ".join(f"{i}->{st['method']} {st['url'][:52]}"
                                   for i, st in enumerate(p.har_steps) if i != (har_step or 0))
                p.note = f"{len(p.har_steps)} SAML hops in capture . --har-step N for: {others}"
            p.params = step["params"]
            p.relay_state = step["params"].get("RelayState")
            candidate = (
                step["params"].get("SAMLResponse")
                or step["params"].get("SAMLRequest")
                or step["body"]
                or step["content"]
            )
            if candidate and "SAMLResponse=" in candidate:
                candidate = urllib.parse.parse_qs(candidate).get("SAMLResponse", [candidate])[0]
            xml = token_to_xml(urllib.parse.unquote(candidate), p) if candidate else None
            if xml:
                p.xml = xml
                p.binding = "HTTP-POST" if step["method"].upper() == "POST" else "HTTP-Redirect"
                return p
            p.error = "HAR hop found, but its SAML message could not be decoded."
            return p
        except (json.JSONDecodeError, KeyError):
            pass

    # ---- raw HTTP request / response capture
    if RAW_HTTP_START.match(text) or ("\nHost:" in text):
        header_block = text.split("\n\n", 1)[0]
        body = text.split("\n\n", 1)[1] if "\n\n" in text else ""
        first = header_block.splitlines()[0]
        m = re.match(r"^(GET|POST)\s+(\S+)\s+HTTP/", first, re.I)
        p.kind = f"Raw HTTP {'request' if m else 'response'} ({first[:60]})"
        target = m.group(2) if m else ""
        q = urllib.parse.parse_qs(urllib.parse.urlparse(target).query)
        form = urllib.parse.parse_qs(body.strip()) if body.strip() else {}
        p.params = {k: v[0] for k, v in {**q, **form}.items()}
        p.relay_state = p.params.get("RelayState")
        for key in ("SAMLResponse", "SAMLRequest"):
            if key in p.params:
                xml = token_to_xml(p.params[key], p)
                if xml:
                    p.xml, p.binding = xml, "HTTP-POST" if key == "SAMLResponse" and form else "HTTP-Redirect"
                    return p
        for chunk in (body, text):
            xml = token_to_xml(chunk, p) if chunk.strip() else None
            if xml:
                p.xml = xml
                return p
        xml = extract_xml_substring(text)
        if xml:
            p.xml, p.chain = xml, p.chain + ["Raw XML"]
            return p
        p.error = "HTTP capture found, but no SAML message could be decoded."
        return p

    # ---- URL with embedded SAML message
    if text.lower().startswith(("http://", "https://")) and len(text.splitlines()) == 1:
        qs = urllib.parse.urlparse(text).query
        params = urllib.parse.parse_qs(qs)
        flat = {k: v[0] for k, v in params.items()}
        p.params = flat
        p.relay_state = flat.get("RelayState")
        p.kind = "Redirect URL"
        if "Signature" in flat:
            p.redirect_sig = {
                "sig_alg": flat.get("SigAlg", ""),
                "signature": flat.get("Signature", ""),
                "relay_state": flat.get("RelayState", ""),
                "query": qs,
            }
        for key in ("SAMLResponse", "SAMLRequest"):
            if key in flat:
                xml = token_to_xml(flat[key], p)
                if xml:
                    p.xml = xml
                    p.binding = "HTTP-Redirect"
                    return p
        p.error = "URL has no SAMLRequest/SAMLResponse query parameter."
        return p

    # ---- HTML auto-submit form
    if "<form" in text.lower() and "SAMLResponse" in text:
        p.kind = "HTML auto-submit form"
        for name in ("SAMLResponse", "SAMLRequest", "RelayState"):
            m = re.search(rf'name=["\']{name}["\'][^>]*value=["\']([^"\']+)', text, re.I)
            if m:
                p.params[name] = m.group(1)
        p.relay_state = p.params.get("RelayState")
        for key in ("SAMLResponse", "SAMLRequest"):
            if key in p.params:
                xml = token_to_xml(p.params[key], p)
                if xml:
                    p.xml, p.binding = xml, "HTTP-POST"
                    return p
        p.error = "HTML form found, but SAML value could not be decoded."
        return p

    # ---- raw XML
    if looks_xml(text.encode("utf-8", "replace")):
        p.xml, p.kind, p.chain = text, "Raw XML", ["Raw XML"]
        return p

    # ---- bare token: base64 / deflate+b64
    flat = urllib.parse.unquote(text)
    xml = token_to_xml(flat, p)
    if xml:
        p.xml = xml
        p.kind = "Base64 token" if "Raw-Deflate" not in p.chain else "Deflated Base64 token"
        p.binding = "HTTP-POST" if "Raw-Deflate" not in p.chain else "HTTP-Redirect"
        return p

    # ---- urlencoded form body
    if "=" in text:
        form = urllib.parse.parse_qs(text)
        if "SAMLResponse" in form or "SAMLRequest" in form:
            p.params = {k: v[0] for k, v in form.items()}
            p.relay_state = p.params.get("RelayState")
            key = "SAMLResponse" if "SAMLResponse" in form else "SAMLRequest"
            xml = token_to_xml(p.params[key], p)
            if xml:
                p.xml, p.kind, p.binding = xml, "Form body", "HTTP-POST"
                return p

    xml = extract_xml_substring(text)
    if xml:
        p.xml, p.kind, p.chain = xml, "Embedded XML", ["Embedded XML"]
        return p

    p.error = ("Could not recognize this as SAML. Tried: HAR, raw HTTP, redirect URL, "
               "HTML form, raw XML, Base64 and Deflate+Base64.")
    return p


def extract_xml_substring(text: str) -> str | None:
    m = re.search(r"(<(?:\?xml|samlp?:Response|samlp?:AuthnRequest|saml:Assertion|md:EntityDescriptor|[\w.-]+:)?[\w.-]*(?:Response|AuthnRequest|Assertion|EntityDescriptor)\b.*?>.*)",
                  text, re.S)
    if not m:
        return None
    return m.group(1).strip()


# ----------------------------------------------------------------------- inspection
def parse_xml(xml_text: str) -> tuple[ET.Element | None, list[str], bool]:
    notes, has_dtd = [], False
    if re.search(r"<!DOCTYPE", xml_text, re.I):
        has_dtd = True
        notes.append("DOCTYPE/ENTITY declaration present - XXE risk (SAML-003)")
        xml_text = re.sub(r"<!DOCTYPE[^>\[]*(\[[^\]]*\])?\s*>", "", xml_text, flags=re.I | re.S)
    try:
        return ET.fromstring(xml_text.encode("utf-8")), notes, has_dtd
    except ET.ParseError as exc:
        return None, notes + [f"XML parse error: {exc}"], has_dtd


def ts(dt_str: str | None) -> datetime | None:
    if not dt_str:
        return None
    try:
        return datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
    except ValueError:
        return None


def rel(dt: datetime | None) -> str:
    if dt is None:
        return ""
    delta = datetime.now(timezone.utc) - dt
    secs = abs(delta.total_seconds())
    unit, val = ("s", secs), None
    for label, size in (("year", 31557600), ("month", 2629800), ("day", 86400), ("hour", 3600), ("minute", 60)):
        if secs >= size:
            val = int(secs // size)
            unit = (label, val)
            break
    if val is None:
        return "just now"
    label, count = unit
    word = label if count == 1 else label + "s"
    return f"{count} {word} ago" if delta.total_seconds() > 0 else f"in {count} {word}"


def fmt_ts(dt_str: str | None) -> str:
    dt = ts(dt_str)
    if dt is None:
        return dt_str or ""
    return f"{dt.astimezone(timezone.utc):%Y-%m-%dT%H:%M:%S}.{dt.microsecond // 1000:03d}Z ({rel(dt)})"


class Report:
    def __init__(self):
        self.common: list[tuple[str, str]] = []
        self.status: list[tuple[str, str, str]] = []
        self.subject: list[tuple[str, str]] = []
        self.conditions: list[tuple[str, str]] = []
        self.attributes: list[tuple[str, str, list[str]]] = []
        self.signatures: list[dict] = []
        self.certs: list[dict] = []
        self.findings: list[dict] = []
        self.meta: list[tuple[str, str]] = []
        self.info: dict = {}


def find_sig(el) -> ET.Element | None:
    for c in el:
        if local(c.tag) == "Signature":
            return c
    return None


def sig_algorithms(sig) -> dict:
    out = {}
    for c in sig.iter():
        n = local(c.tag)
        if n in ("SignatureMethod", "DigestMethod", "CanonicalizationMethod"):
            out[n] = re.split(r"[#/]", (c.get("Algorithm") or "").rstrip("#"))[-1]
        if n == "Reference":
            out["Reference"] = c.get("URI", "").lstrip("#")
        if n == "DigestValue" and txt(c) and "DigestValue" not in out:
            out["DigestValue"] = txt(c)
        if n == "SignatureValue" and txt(c) and "SignatureValue" not in out:
            out["SignatureValue"] = txt(c)
    return out


def short_alg(alg: str) -> str:
    return re.sub(r"^(rsa-|ecdsa-|hmac-)", "", alg.lower())


def build_report(p: Payload, xml: str, cert_path: str | None) -> Report:
    r = Report()
    root, notes, has_dtd = parse_xml(xml)
    if root is None:
        r.findings.append({"id": "SAML-000", "sev": "CRITICAL", "msg": "; ".join(notes) or "Unparseable XML"})
        return r

    mt = local(root.tag)
    r.info["type"] = mt
    now = datetime.now(timezone.utc)

    # ---- COMMON
    r.common.append(("Type", mt))
    if root.get("Version"):
        r.common.append(("Version", root.get("Version")))
    if p.binding:
        r.common.append(("Binding", p.binding))
    issuer = txt(child(root, "Issuer"))
    if issuer:
        r.common.append(("Issuer", issuer))
    if root.get("Destination"):
        r.common.append(("Destination", root.get("Destination")))
    if root.get("IssueInstant"):
        r.common.append(("IssueInstant", fmt_ts(root.get("IssueInstant"))))
    if root.get("InResponseTo"):
        r.common.append(("InResponseTo", root.get("InResponseTo")))
    if p.relay_state:
        r.common.append(("RelayState", p.relay_state))
    if root.get("entityID"):
        r.common.append(("EntityID", root.get("entityID")))

    # ---- STATUS
    st = child(root, "Status")
    if st is not None:
        code_el = child(st, "StatusCode")
        code = code_el.get("Value", "") if code_el is not None else ""
        label = STATUS_NAMES.get(code, code.rsplit(":", 1)[-1] or "Unknown")
        good = code.endswith(":Success")
        r.status.append(("Status", label, "green" if good else "red"))
        if code and not good:
            r.status.append(("StatusCode", code, "dim"))
        sub = child(code_el, "StatusCode") if code_el is not None else None
        if sub is not None:
            r.status.append(("SubStatusCode", sub.get("Value", ""), "dim"))
        msg = txt(child(st, "StatusMessage"))
        if msg:
            r.status.append(("StatusMessage", msg, "amber"))

    # ---- assertions
    asserts = [root] if mt == "Assertion" else [c for c in root if local(c.tag) == "Assertion"]
    enc_asserts = [c for c in root.iter() if local(c.tag) == "EncryptedAssertion"]
    if enc_asserts:
        r.findings.append({"id": "SAML-015", "sev": "HIGH",
                           "msg": "EncryptedAssertion present - decrypt with `samlx decrypt --key sp.key` to inspect claims"})
        r.common.append(("Encrypted", f"{len(enc_asserts)} encrypted assertion(s)"))

    primary = asserts[0] if asserts else None
    if primary is not None:
        subj = child(primary, "Subject")
        nid_el = child(subj, "NameID") if subj is not None else None
        if nid_el is not None:
            nid = txt(nid_el)
            r.subject.append(("NameID", nid))
            if nid_el.get("Format"):
                r.subject.append(("NameID Format", nid_el.get("Format", "").rsplit(":", 1)[-1]))
        scd = None
        for cand in primary.iter():
            if local(cand.tag) == "SubjectConfirmationData":
                scd = cand
                break
        if scd is not None:
            if scd.get("Recipient"):
                r.subject.append(("Recipient", scd.get("Recipient")))
            if scd.get("InResponseTo"):
                r.subject.append(("Subject InResponseTo", scd.get("InResponseTo")))
            if scd.get("NotOnOrAfter"):
                r.subject.append(("Subject NotOnOrAfter", fmt_ts(scd.get("NotOnOrAfter"))))

        for cand in primary.iter():
            if local(cand.tag) == "AuthnStatement":
                if cand.get("SessionIndex"):
                    r.subject.append(("SessionIndex", cand.get("SessionIndex")))
                if cand.get("AuthnInstant"):
                    r.subject.append(("AuthnInstant", fmt_ts(cand.get("AuthnInstant"))))
                for c2 in cand.iter():
                    if local(c2.tag) == "AuthnContextClassRef" and txt(c2):
                        r.subject.append(("AuthnContext", txt(c2).rsplit(":", 1)[-1]))
                break

        cond = child(primary, "Conditions")
        if cond is not None:
            nb, noa = cond.get("NotBefore"), cond.get("NotOnOrAfter")
            if nb:
                r.conditions.append(("NotBefore", fmt_ts(nb)))
            if noa:
                r.conditions.append(("NotOnOrAfter", fmt_ts(noa)))
            audiences = [txt(a) for a in cond.iter() if local(a.tag) == "Audience" and txt(a)]
            if audiences:
                r.conditions.append(("Audience", ", ".join(audiences)))
            nb_dt, noa_dt = ts(nb), ts(noa)
            state = ("EXPIRED", "red") if noa_dt and now >= noa_dt else \
                    ("NOT YET VALID", "amber") if nb_dt and now < nb_dt else ("ACTIVE", "green")
            r.conditions.append(("Validity", state[0], ))
            r.info["validity"] = state
            if noa_dt and now >= noa_dt:
                r.findings.append({"id": "SAML-011", "sev": "HIGH", "msg": "Assertion expired (Conditions/NotOnOrAfter is in the past)"})
            if nb_dt and noa_dt and (noa_dt - nb_dt).total_seconds() > 3600:
                r.findings.append({"id": "SAML-010", "sev": "MEDIUM", "msg": "Assertion lifetime exceeds 60 minutes"})
            if not audiences:
                r.findings.append({"id": "SAML-012", "sev": "HIGH", "msg": "Missing <AudienceRestriction> - assertion replayable at any SP"})
        else:
            r.findings.append({"id": "SAML-010", "sev": "HIGH", "msg": "Assertion has no <Conditions> element"})

        for stmt in primary.iter():
            if local(stmt.tag) != "AttributeStatement":
                continue
            for attr in stmt:
                if local(attr.tag) != "Attribute":
                    continue
                vals = [txt(v) for v in attr if local(v.tag) == "AttributeValue"]
                r.attributes.append((attr.get("Name", "(unnamed)"), attr.get("FriendlyName", ""), vals))
            break

        if not root.get("InResponseTo") and mt == "Response":
            r.findings.append({"id": "SAML-014", "sev": "LOW", "msg": "Unsolicited / IdP-initiated response (no InResponseTo)"})

    # ---- certificate input
    if cert_path:
        try:
            cert_text = open(os.path.expanduser(cert_path), "r", errors="replace").read()
        except OSError as exc:
            r.findings.append({"id": "CERT", "sev": "AMBER", "msg": f"Could not read --cert {cert_path}: {exc}"})
        else:
            for m in re.finditer(r"<(?:\w+:)?X509Certificate[^>]*>([^<]+)</", cert_text):
                info = cert_info(m.group(1))
                if info:
                    info["source"] = "IdP Metadata (signing)"
                    r.certs.append(info)
                    break
            else:
                info = cert_info(cert_text)
                if info:
                    info["source"] = f"Pinned file ({os.path.basename(cert_path)})"
                    r.certs.append(info)
                else:
                    r.findings.append({"id": "CERT", "sev": "AMBER", "msg": f"--cert {cert_path} is not a readable X.509 certificate"})

    # ---- fingerprints available for verification
    p.pinned_pubs = [c["rsa_pub"] for c in r.certs if c.get("rsa_pub") and "Pinned" in c.get("source", "") or
                     c.get("rsa_pub") and "Metadata" in c.get("source", "")]
    pinned_pubs = p.pinned_pubs
    embedded_pubs: dict[str, list] = {"outer": [], "inner": []}

    # ---- signatures
    outer_sig = find_sig(root)
    inner_sig = find_sig(primary) if primary is not None else None
    sig_rows = [(f"SAML {mt}", outer_sig, "outer")]
    if mt in ("Response", "LogoutResponse") and primary is not None:
        sig_rows.append(("SAML Assertion", inner_sig, "inner"))
    for label, sig, where in sig_rows:
        if sig is None:
            r.signatures.append({"label": label, "state": "Not signed", "style": "grey",
                                 "alg": "", "ref": "", "where": where})
            continue
        algs = sig_algorithms(sig)
        digest = short_alg(algs.get("DigestMethod", ""))

        cert_el = None
        for c in sig.iter():
            if local(c.tag) == "X509Certificate" and txt(c):
                cert_el = c
                break
        keyinfo = None
        if cert_el is not None:
            keyinfo = cert_info(txt(cert_el))
            if keyinfo:
                keyinfo["source"] = f"{label} KeyInfo"
                r.certs.append(keyinfo)
                embedded_pubs[where].append(keyinfo.get("rsa_pub"))
                if keyinfo.get("rsa_pub"):
                    p.embedded_pubs.append(keyinfo["rsa_pub"])

        state, style, detail = "Present (unverified)", "amber", ""
        if p.redirect_sig and where == "outer":
            state, style, detail = verify_redirect(p)
        else:
            pubs = pinned_pubs + embedded_pubs[where]
            result, why = verify_xml_signature(p.xml, algs.get("Reference", ""), algs, pubs[0] if pubs else None)
            if result is True:
                pinned = bool(pinned_pubs) and (pubs[:1] == pinned_pubs[:1])
                state = "Valid Signature" + (" (pinned key)" if pinned else " (embedded key)")
                style, detail = "green", why
            elif result is False:
                state, style, detail = "INVALID SIGNATURE", "red", why
            else:
                state, style, detail = "Present (unverified)", "amber", why

        if "sha1" in digest or "md5" in digest:
            r.findings.append({"id": "SAML-006", "sev": "HIGH", "msg": f"Weak digest algorithm ({digest}) in {label} signature"})
        if state == "INVALID SIGNATURE":
            r.findings.append({"id": "SAML-002", "sev": "CRITICAL", "msg": f"{label} signature failed verification: {detail}"})
        if isinstance(keyinfo, dict) and pinned_pubs and keyinfo.get("rsa_pub") not in pinned_pubs:
            r.findings.append({"id": "SAML-002", "sev": "HIGH",
                               "msg": f"{label} is signed by a key that does not match the pinned --cert"})
        r.signatures.append({
            "label": label,
            "state": state,
            "style": style,
            "alg": algs.get("SignatureMethod", ""),
            "digest": digest,
            "c14n": algs.get("CanonicalizationMethod", ""),
            "ref": algs.get("Reference", ""),
            "detail": detail,
            "where": where,
        })

    if p.redirect_sig:
        rstate, rstyle, rdetail = verify_redirect(p)
        r.signatures.append({"label": "Redirect Query", "state": rstate, "style": rstyle,
                             "alg": (p.redirect_sig.get("sig_alg") or "").rsplit("#", 1)[-1],
                             "digest": (p.redirect_sig.get("sig_alg") or "").rsplit("-", 1)[-1],
                             "ref": p.redirect_sig.get("query", "")[:0], "detail": rdetail, "where": "redirect"})
        if rstate == "INVALID SIGNATURE":
            r.findings.append({"id": "SAML-002", "sev": "CRITICAL",
                               "msg": f"HTTP-Redirect signature invalid: {rdetail}"})
        if not rdetail.startswith("no signing") and rstate.startswith("Present"):
            r.findings.append({"id": "SAML-005", "sev": "AMBER",
                               "msg": "Redirect signature present but unverified - pass --cert to pin the IdP key"})

    if mt == "Response" and outer_sig is None and inner_sig is None:
        r.findings.append({"id": "SAML-001", "sev": "CRITICAL", "msg": "Message is completely unsigned"})
    if mt == "Response" and outer_sig is not None and inner_sig is None:
        r.findings.append({"id": "SAML-005", "sev": "LOW", "msg": "Only the Response is signed - assertion itself unprotected if response signature is not enforced"})
    if mt == "Response" and outer_sig is None and inner_sig is not None:
        r.findings.append({"id": "SAML-005", "sev": "MEDIUM", "msg": "Only the Assertion is signed - Response envelope unsigned"})


    # ---- cert hygiene
    for cert in r.certs:
        nb, na = cert.get("not_before"), cert.get("not_after")
        if na and now > na:
            r.findings.append({"id": "SAML-007", "sev": "HIGH", "msg": f"Signing certificate expired on {na:%Y-%m-%d}"})
        if nb and now < nb:
            r.findings.append({"id": "SAML-007", "sev": "AMBER", "msg": f"Certificate not valid until {nb:%Y-%m-%d}"})
        if cert.get("key", "").startswith("RSA") and cert["key"].split()[-1].isdigit() and int(cert["key"].split()[-1]) < 2048:
            r.findings.append({"id": "SAML-007", "sev": "HIGH", "msg": f"Weak {cert['key']} signing key"})

    # ---- transport / misc
    transport_blob = " ".join([root.get("Destination", ""), issuer, p.relay_state or ""])
    for h in re.findall(r"http://[^\s\"'<>]+", transport_blob):
        r.findings.append({"id": "SAML-015", "sev": "MEDIUM", "msg": f"Plaintext HTTP endpoint: {h}"})
        break
    if has_dtd:
        r.findings.append({"id": "SAML-003", "sev": "CRITICAL", "msg": "XML carries a DOCTYPE - XXE / entity expansion vector"})
    if re.search(r"<!--", xml):
        r.findings.append({"id": "SAML-009", "sev": "HIGH", "msg": "XML comments present - some parsers truncate NameID text (CVE-2017-11427)"})
    if len(asserts) > 1:
        r.findings.append({"id": "SAML-004", "sev": "CRITICAL", "msg": f"{len(asserts)} assertions in one Response - signature-wrapping (XSW) surface"})
    for note in notes:
        if "parse error" in note.lower():
            r.findings.append({"id": "SAML-000", "sev": "CRITICAL", "msg": note})

    # metadata quick summary
    if mt == "EntityDescriptor":
        for svc in ("SingleSignOnService", "AssertionConsumerService", "SingleLogoutService"):
            for el in root.iter():
                if local(el.tag) == svc:
                    r.meta.append((svc, f"{el.get('Binding', '').rsplit(':', 1)[-1]} -> {el.get('Location', '')}"))
    return r


def verify_redirect(p: Payload) -> tuple[str, str, str]:
    """Verify a HTTP-Redirect binding signature (SAML Bindings 3.4.4.1) over the raw query."""
    sig = p.redirect_sig or {}
    if not sig.get("signature"):
        return "Not signed", "grey", ""
    query = sig["query"]
    # The signature covers the *raw* (still percent-encoded) query octets with the
    # Signature parameter removed - never a re-serialized, decoded version.
    segments = [seg for seg in query.split("&") if seg and not seg.startswith("Signature=")]
    signed = "&".join(segments)
    alg = sig.get("sig_alg", "")
    digest_name = "sha384" if "sha384" in alg else "sha512" if "sha512" in alg \
        else "sha1" if "sha1" in alg else "sha256"
    try:
        signature = base64.b64decode(urllib.parse.unquote(sig["signature"]) + "===")
    except (binascii.Error, ValueError):
        return "INVALID SIGNATURE", "red", "Signature parameter is not valid Base64"
    pub = (p.pinned_pubs or p.embedded_pubs or [None])[0]
    if pub is None:
        return "Present (unverified)", "amber", "no signing certificate supplied - pass --cert idp.pem"
    ok = rsa_pkcs1_verify(tuple(pub), signed.encode("utf-8"), signature, digest_name)
    if ok:
        return ("Valid Signature", "green",
                f"{digest_name.upper()} over the raw redirect query string (pinned key)")
    return ("INVALID SIGNATURE", "red",
            "digest mismatch - query string was modified after the IdP signed it")


HAVE_SAMLX = False
try:  # optional boost: full XMLDSig + decryption engine from the samlx suite
    import samlx  # type: ignore  # noqa: F401
    HAVE_SAMLX = True
except Exception:
    HAVE_SAMLX = False


# ------------------------------------------------------------------------- rendering
BORDER = "╭╮╰╯─│├┤"


def stylize(style: str, text: str) -> str:
    palette = {
        "green": C.GREEN, "red": C.RED, "amber": C.AMBER, "grey": C.GREY,
        "cyan": C.CYAN, "white": C.WHITE, "mag": C.MAG, "lime": C.LIME, "dim": C.DIM,
    }
    code = palette.get(style, "")
    return f"{col(code)}{text}{col(C.R)}" if code else text


def panel(title: str, rows: list, width: int, accent: str | None = None, badge: str = "") -> list[str]:
    accent = accent if accent is not None else C.BLUE
    """Draw one rounded neon box: title in the top border, key/value rows right aligned."""
    inner = width - 2
    head = f" {title.upper()} "
    if badge:
        head = f" {title.upper()} " + stylize("dim", f"[{badge}]") + " "
    fill = max(0, inner - w(head) - 1)
    out = [
        f"{col(accent)}╭─{col(C.BOLD)}{col(C.CYAN)}{head}{col(C.R)}{col(accent)}{'─' * fill}╮{col(C.R)}"
    ]
    body: list[tuple[str, str]] = []
    for row in rows:
        if not row:
            continue
        kind = row[0]
        if kind == "kv":
            body.append(("kv", row[1], row[2], row[3] if len(row) > 3 else "white"))
        elif kind == "sep":
            body.append(("sep", "", "", ""))
        elif kind == "attr":
            body.append(("attr", row[1], row[2], ""))
        elif kind == "blank":
            body.append(("blank", "", "", ""))
    body.insert(0, ("blank", "", "", ""))
    for i, (kind, key, val, style) in enumerate(body):
        if i:
            out.append(f"{col(accent)}├{'─' * inner}┤{col(C.R)}")
        if kind == "blank":
            out.append(f"{col(accent)}│{col(C.R)}{' ' * inner}{col(accent)}│{col(C.R)}")
            continue
        if kind == "attr":
            key_s = f"{col(C.BOLD)}{col(C.ICE)}{key}{col(C.R)}"
            if w(key) > inner - 2:
                chunks = textwrap.wrap(key, inner - 2)
                out.append(f"{col(accent)}│{col(C.R)} {key_s if w(chunks[0]) == w(key) else chunks[0]}{' ' * (inner - 1 - w(chunks[0]))}{col(accent)}│{col(C.R)}")
                for extra in chunks[1:]:
                    out.append(f"{col(accent)}│{col(C.R)} {extra}{' ' * (inner - 1 - w(extra))}{col(accent)}│{col(C.R)}")
            else:
                out.append(f"{col(accent)}│{col(C.R)} {key_s}{' ' * (inner - 1 - w(key))}{col(accent)}│{col(C.R)}")
            for v in val:
                wrapped = textwrap.wrap(v, inner - 3) or [""]
                for j, line in enumerate(wrapped):
                    pre = "   " if j else "  "
                    shown = v if len(wrapped) == 1 else line
                    if len(wrapped) == 1:
                        shown = clip(shown, inner - 2)
                    out.append(f"{col(accent)}│{col(C.R)}{pre}{col(C.WHITE)}{shown}{col(C.R)}"
                               f"{' ' * (inner - w(pre) - w(shown))}{col(accent)}│{col(C.R)}")
            continue
        # key/value
        label = f"{col(C.WHITE)}{key}{col(C.R)}"
        val_plain = str(val)
        avail = inner - 4 - w(key)
        if w(val_plain) <= avail:
            line = f" {label}{' ' * (inner - 2 - w(key) - w(val_plain))}{stylize(style, val_plain)}{col(C.R)}"
            out.append(f"{col(accent)}│{col(C.R)}{line}{col(accent)}│{col(C.R)}")
        else:
            out.append(f"{col(accent)}│{col(C.R)} {label}{' ' * (inner - 2 - w(key))}{col(accent)}│{col(C.R)}")
            for line in textwrap.wrap(val_plain, inner - 3) or [""]:
                out.append(f"{col(accent)}│{col(C.R)}  {stylize(style, line)}"
                           f"{' ' * (inner - 2 - w(line))}{col(accent)}│{col(C.R)}")
    out.append(f"{col(accent)}╰{'─' * inner}╯{col(C.R)}")
    return out


def side_by_side(left: list[list[str]], right: list[list[str]], gap: int = 2,
                 pad_width: int = 0) -> list[str]:
    lines: list[str] = []
    colw_pad = [pad_width or (w(left[0][0]) if left and left[0] else 0)]
    rows = [[] if i >= len(left) else left[i] for i in range(max(len(left), len(right)))]
    cols = [[] if i >= len(right) else right[i] for i in range(max(len(left), len(right)))]
    for lpan, rpan in zip(rows, cols):
        height = max(len(lpan), len(rpan))
        lw = w(lpan[0]) if lpan else 0
        for i in range(height):
            lline = lpan[i] if i < len(lpan) else " " * colw_pad[0]
            rline = rpan[i] if i < len(rpan) else ""
            lines.append(f"{lline}{' ' * gap}{rline}".rstrip())
    return lines


def banner(width: int) -> list[str]:
    art = [
        r"  ____    _    __  __ _        _   _ _   _ ____  ",
        r" / ___|  / \  |  \/  | |      | | | | | | |  _ \ ",
        r" \___ \ / _ \ | |\/| | |      | |_| | | | | | | |",
        r"  ___) / ___ \| |  | | |___   |  _  | |_| | |_| |",
        r" |____/_/   \_\_|  |_|_____|  |_| |_|\___/|____/ ",
    ]
    accent, accent2 = C.CYAN, C.MAG
    out = [""]
    for i, line in enumerate(art):
        color = accent if i % 2 == 0 else accent2
        tag = ""
        if i == 2:
            tag = f"  {col(C.DIM)}v{VERSION}{col(C.R)}"
        out.append(f"{col(color)}{col(C.BOLD)}{line}{col(C.R)}{tag}")
    out.append(
        f"{col(C.GREY)}  :: SAML 2.0 decode . inspect . verify . audit"
        f"{' ' * max(0, width - 62)}{col(C.DIM)}kali edition{col(C.R)}{col(C.GREY)} ::{col(C.R)}"
    )
    out.append("")
    return out


def header_line(left: str, right: str, width: int) -> str:
    return (f"{col(C.PURP)}▐{col(C.R)} {left}"
            f"{' ' * max(1, width - w(left) - w(right) - 4)}{right} "
            f"{col(C.PURP)}▌{col(C.R)}")


def render(p: Payload, r: Report, width: int, elapsed: float, source: str, title_note: str = "") -> None:
    out: list[str] = banner(width)
    src = f"{col(C.ICE)}{source}{col(C.R)}"
    out.append(header_line(
        f"{col(C.BOLD)}{col(C.WHITE)}INPUT{col(C.R)} {src}",
        f"{col(C.DIM)}{p.raw_size} B . decoded in {elapsed * 1000:.1f} ms{col(C.R)}", width))
    chain = " -> ".join(p.chain) if p.chain else "raw"
    out.append(header_line(
        f"{col(C.BOLD)}{col(C.WHITE)}DECODE{col(C.R)} {col(C.LIME)}{chain}{col(C.R)}"
        + (f" {col(C.DIM)}. {clip(title_note, max(0, width - 70))}{col(C.R)}" if title_note else ""),
        f"{col(C.DIM)}{p.kind or 'unknown'}{col(C.R)}", width))
    out.append("")
    out.append("")

    if p.error:
        out.append(f"{col(C.RED)}{col(C.BOLD)} [!] {p.error}{col(C.R)}")
        out.append("")
        out.append(f"{col(C.DIM)}  hint: paste a SAMLResponse token, a ?SAMLRequest=... URL, raw XML, "
                   f"a Burp request or a .har file. Use --demo for a built-in sample.{col(C.R)}")
        print("\n".join(out))
        return

    two_col = width >= 84
    colw = (width - 1) // 2 if two_col else width

    sig_styles = {"green": "green", "red": "red", "amber": "amber", "grey": "grey"}
    left = [
        panel("common", [("kv", k, v, "cyan") for k, v in r.common], colw),
        panel("signature", [("kv", s["label"], s["state"], sig_styles.get(s["style"], "white"))
                            for s in r.signatures]
              + ([("kv", "Algorithm", f"{s['alg']} / {s.get('digest', '')}", "dim") for s in r.signatures if s["alg"]][:1]),
              colw, C.MAG),
    ]
    if r.certs:
        cert = r.certs[0]
        nb, na = cert.get("not_before"), cert.get("not_after")
        rows = [
            ("kv", "Subject", cert.get("subject", "")[:60] or "n/a", "white"),
            ("kv", "Issuer", cert.get("issuer", "")[:60] or "n/a", "dim"),
            ("kv", "Source", cert.get("source", ""), "dim"),
            ("kv", "SerialNumber", cert.get("serial", ""), "cyan"),
            ("kv", "Thumbprint", (cert.get("sha1") or "").replace(":", "").lower(), "cyan"),
            ("kv", "SHA-256", (cert.get("sha256") or "").replace(":", "").lower(), "dim"),
        ]
        if nb and na:
            rows.append(("kv", "Validity", f"{nb:%Y-%m-%d} -> {na:%Y-%m-%d}", "white"))
        if cert.get("key"):
            rows.append(("kv", "Public Key", cert["key"], "cyan"))
        left.append(panel("certificate", rows, colw, C.PURP))

    right = []
    if r.status:
        right.append(panel("status", [("kv", "Status", v, s) for _, v, s in r.status], colw, C.LIME))
    if r.subject:
        key_rows = [("kv", k, v, "white") for k, v in r.subject]
        right.append(panel("assertion", key_rows, colw, C.ICE))
    if r.conditions:
        rows = []
        for row in r.conditions:
            k, v = row[0], row[1]
            style = "red" if v.startswith("EXPIRED") else "green" if v.startswith("ACTIVE") else \
                    "amber" if v.startswith("NOT") else "white"
            rows.append(("kv", k, v, style))
        right.append(panel("conditions", rows, colw, C.AMBER))
    if r.meta:
        right.append(panel("metadata endpoints", [("kv", k, v, "cyan") for k, v in r.meta], colw, C.BLUE))
    if r.attributes:
        rows = []
        for name, friendly, vals in r.attributes:
            label = name
            if friendly and friendly != name:
                label = name if len(name) > 34 else f"{name}  [{friendly}]"
            rows.append(("attr", label, vals or ["(empty)"]))
        right.append(panel("attributes", rows, colw, C.CYAN))
    if not right:
        right.append(panel("details", [("kv", "Note", "Nothing further to show for this message type", "dim")], colw))

    if two_col:
        out.extend(side_by_side(left, right, pad_width=colw))
    else:
        for pan in left + right:
            out.extend(pan)

    out.append("")
    out.extend(render_audit(r, width))
    out.append(render_footer(r, width))
    print("\n".join(out))


def render_audit(r: Report, width: int) -> list[str]:
    sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "AMBER": 2}
    findings = sorted(r.findings, key=lambda f: sev_rank.get(f["sev"], 5))
    icon = {"CRITICAL": "✖", "HIGH": "▲", "MEDIUM": "◆", "LOW": "•", "INFO": "i", "AMBER": "!"}
    color = {"CRITICAL": C.RED, "HIGH": C.ROSE, "MEDIUM": C.AMBER, "LOW": C.CYAN, "INFO": C.GREY, "AMBER": C.AMBER}
    head = (f"{col(C.BOLD)}{col(C.MAG)}┏━ SECURITY AUDIT "
            f"{'━' * max(0, width - 22)}{col(C.R)}")
    lines = [head]
    if not findings:
        lines.append(f"{col(C.LIME)}  ✔ no findings - message is signed, scoped and inside its validity window{col(C.R)}")
    body_w = width - 12
    for f in findings[:14]:
        tag = f"{f['sev']:<8}"
        lines.append(
            f"{col(C.MAG)}┃{col(C.R)} {col(C.BOLD)}{col(color.get(f['sev'], C.WHITE))}{icon.get(f['sev'], '•')} "
            f"{tag}{col(C.R)}{col(C.DIM)}{f['id']}{col(C.R)}  "
            f"{col(C.WHITE)}{clip(f['msg'], body_w)}{col(C.R)}")
    if len(findings) > 14:
        lines.append(f"{col(C.MAG)}┃{col(C.R)} {col(C.DIM)}... {len(findings) - 14} more finding(s){col(C.R)}")
    counts = {}
    for f in findings:
        counts[f["sev"]] = counts.get(f["sev"], 0) + 1
    tally = "  ".join(f"{col(color.get(k, C.WHITE))}{k}:{v}{col(C.R)}" for k, v in counts.items()) or \
        f"{col(C.LIME)}CLEAN{col(C.R)}"
    lines.append(f"{col(C.MAG)}┗━{col(C.R)} {tally}")
    lines.append("")
    return lines


def render_footer(r: Report, width: int) -> str:
    state = r.info.get("validity", ("", ""))
    bits = [
        f"{col(C.DIM)}type{col(C.R)} {col(C.WHITE)}{r.info.get('type', '?')}{col(C.R)}",
        f"{col(C.DIM)}sig{col(C.R)} " + ", ".join(
            f"{stylize(s['style'], s['state'])}" for s in r.signatures) if r.signatures else "",
        f"{col(C.DIM)}window{col(C.R)} {stylize(state[1] if len(state) > 1 else 'white', state[0] or 'n/a')}",
        f"{col(C.DIM)}engine{col(C.R)} {col(C.LIME) + 'samlx' + col(C.R) if HAVE_SAMLX else col(C.GREY) + 'stdlib' + col(C.R)}",
        f"{col(C.DIM)}color{col(C.R)} {col(C.WHITE)}{COLOR_MODE}{col(C.R)}",
    ]
    bar = f"  {col(C.DIM)}|{col(C.R)}  ".join(b for b in bits if b)
    line = f"{col(C.BLUE)}{'─' * width}{col(C.R)}"
    return f"{line}\n{bar}"


# ----------------------------------------------------------------------------- input
def read_input(args: list[str]) -> tuple[str, str]:
    files = [a for a in args if not a.startswith("-")]
    if files:
        path = files[0]
        if path == "-":
            return sys.stdin.read(), "stdin"
        if os.path.exists(os.path.expanduser(path)):
            with open(os.path.expanduser(path), "r", errors="replace") as fh:
                return fh.read(), os.path.basename(path)
        if path.lower().startswith("http://") or path.lower().startswith("https://"):
            return path, "url argument"
        return path, "inline argument"   # token passed directly on the command line

    if not sys.stdin.isatty():
        return sys.stdin.read(), "stdin pipe"

    print(f"{col(C.CYAN)}{col(C.BOLD)}┏━ PASTE SAML INPUT "
          f"{'━' * 48}{col(C.R)}")
    print(f"{col(C.CYAN)}┃{col(C.R)} {col(C.WHITE)}SAMLResponse / SAMLRequest token, redirect URL, raw XML,{col(C.R)}")
    print(f"{col(C.CYAN)}┃{col(C.R)} {col(C.WHITE)}Burp request, HTML form or .har path - then press Ctrl-D{col(C.R)}")
    print(f"{col(C.CYAN)}┗{'━' * 65}{col(C.R)}")
    sys.stdout.write(f"{col(C.LIME)}> {col(C.R)}")
    sys.stdout.flush()
    data = sys.stdin.read()
    print()
    return data, "interactive paste"


USAGE = f"""{col(C.CYAN)}SAML HUD{col(C.R)} - zero-install SAML 2.0 terminal inspector

{col(C.WHITE)}usage{col(C.R)}
  saml-hud.sh                     interactive paste mode (Ctrl-D to analyze)
  saml-hud.sh <file>              .b64 / .xml / .http / .har / .txt capture
  saml-hud.sh '<url>'             redirect URL with ?SAMLRequest=... / ?SAMLResponse=...
  saml-hud.sh '<token>'           base64 or deflate+base64 token
  cat capture.http | saml-hud.sh  stdin pipe

{col(C.WHITE)}options{col(C.R)}
  -c, --cert FILE     pinned IdP/SP certificate (PEM, bare base64 or metadata XML)
  -f, --file FILE     input file (same as positional)
  -H, --har-step N    which SAML hop to inspect inside a .har capture
      --xml           print only the decoded XML (pipe to xmllint / grep)
      --pem           print the signing certificate PEM after the report
      --json          machine readable output (jq friendly)
      --color MODE    force color depth: truecolor | 256 | 16 | mono
      --no-color      disable ANSI colors (also honours NO_COLOR)
      --demo          run against a built-in encrypted-free demo response
  -h, --help          this screen
"""

DEMO_XML = """<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="_d71a3a8e9fcc45c9e9d248ef7049393fc8f04e5f75" Version="2.0"
    IssueInstant="2026-11-24T10:14:32Z" Destination="https://app.kali-lab.local/saml/acs"
    InResponseTo="_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6">
  <saml:Issuer>urn:kali-lab:idp</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion ID="_a1b2c3d4" Version="2.0" IssueInstant="2026-11-24T10:14:32Z">
    <saml:Issuer>urn:kali-lab:idp</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">ghost@kali-lab.local</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="2026-11-24T10:19:32Z"
            Recipient="https://app.kali-lab.local/saml/acs"
            InResponseTo="_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="2026-11-24T10:14:02Z" NotOnOrAfter="2026-11-24T10:19:32Z">
      <saml:AudienceRestriction>
        <saml:Audience>https://app.kali-lab.local/saml</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="2026-11-24T10:14:31Z" SessionIndex="_sess_9ff21">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
                      FriendlyName="email">
        <saml:AttributeValue>ghost@kali-lab.local</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="role" FriendlyName="role">
        <saml:AttributeValue>admin</saml:AttributeValue>
        <saml:AttributeValue>pentester</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>"""


def main(argv: list[str]) -> int:
    global ENABLED, COLOR_MODE, C
    try:  # behave like a normal unix filter when piped into head/less
        import signal
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    except (ImportError, AttributeError, ValueError):
        pass
    args, cert_path, har_step, as_json = [], None, None, False
    want_xml = want_pem = False
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ("-h", "--help"):
            print(USAGE)
            return 0
        elif a in ("-c", "--cert") and i + 1 < len(argv):
            cert_path = argv[i + 1]
            i += 1
        elif a in ("-f", "--file") and i + 1 < len(argv):
            args.append(argv[i + 1])
            i += 1
        elif a in ("-H", "--har-step") and i + 1 < len(argv):
            har_step = int(argv[i + 1])
            i += 1
        elif a == "--json":
            as_json = True
        elif a == "--xml":
            want_xml = True
        elif a == "--pem":
            want_pem = True
        elif a == "--color" and i + 1 < len(argv):
            os.environ["SAML_HUD_COLOR"] = argv[i + 1]
            i += 1
        elif a == "--no-color":
            os.environ["SAML_HUD_COLOR"] = "mono"
            ENABLED = False
        elif a == "--demo":
            args.append("__demo__")
        elif a.startswith("-") and a != "-":
            print(f"{col(C.RED)}unknown option: {a}{col(C.R)}")
            print(USAGE)
            return 2
        else:
            args.append(a)
        i += 1

    if os.environ.get("SAML_HUD_COLOR"):
        COLOR_MODE = _detect_color_mode()
        apply_theme()
        ENABLED = COLOR_MODE != "none"

    try:
        width = min(148, max(72, __import__("shutil").get_terminal_size((110, 30)).columns))
    except OSError:
        width = 110

    if args and args[0] == "__demo__":
        raw, source = DEMO_XML, "built-in demo"
    else:
        raw, source = read_input(args)

    if not raw.strip():
        print(f"{col(C.RED)}[!] empty input{col(C.R)}")
        return 1

    t0 = time.time()
    payload = decode_input(raw, har_step)
    elapsed = time.time() - t0

    if want_xml and payload.xml:
        print(payload.xml)
        return 0

    if as_json:
        report = build_report(payload, payload.xml, cert_path) if payload.xml else Report()
        print(json.dumps({
            "tool": f"{TOOL} {VERSION}",
            "source": source,
            "kind": payload.kind,
            "decode_chain": payload.chain,
            "binding": payload.binding,
            "error": payload.error,
            "common": dict(report.common),
            "status": [v for _, v, _ in report.status],
            "assertion": dict(report.subject),
            "conditions": [(r[0], r[1]) for r in report.conditions],
            "attributes": [
                {"name": n, "friendly": f, "values": v} for n, f, v in report.attributes
            ],
            "signatures": [
                {k: s[k] for k in ("label", "state", "alg", "digest", "ref") if k in s}
                for s in report.signatures
            ],
            "certificates": [
                {"source": c.get("source"), "subject": c.get("subject"), "issuer": c.get("issuer"),
                 "serial": c.get("serial"), "sha1": c.get("sha1", "").replace(":", ""),
                 "sha256": c.get("sha256", "").replace(":", ""),
                 "not_before": str(c.get("not_before")), "not_after": str(c.get("not_after"))}
                for c in report.certs
            ],
            "findings": report.findings,
            "xml": payload.xml,
        }, indent=2))
        return 0 if payload.xml else 3

    if not payload.xml:
        render(payload, Report(), width, elapsed, source)
        return 3

    report = build_report(payload, payload.xml, cert_path)
    render(payload, report, width, elapsed, source, payload.note)

    if want_pem:
        for cert in report.certs:
            print(f"{col(C.GREY)}# {cert.get('source', 'certificate')}{col(C.R)}")
            print(cert.get("pem", "").strip())

    critical = any(f["sev"] in ("CRITICAL", "HIGH") for f in report.findings)
    return 2 if critical else 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except KeyboardInterrupt:
        print(f"\n{col(C.GREY)}aborted{col(C.R)}")
        sys.exit(130)
    except BrokenPipeError:
        try:
            devnull = os.open(os.devnull, os.O_WRONLY)
            os.dup2(devnull, sys.stdout.fileno())
        except OSError:
            pass
        sys.exit(0)
#__PY_END__
SAML_HUD_PY_BODY
