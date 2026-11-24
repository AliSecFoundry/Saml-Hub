#!/usr/bin/env python3
"""Regenerate the synthetic sample corpus in samples/.

The tokens are minted with *fresh* timestamps at generation time so the signed
samples always sit inside their validity window when someone runs the tests.

Requires the optional helper package `samlx` (pip install -e ../samlx) because
signing/encryption is easier to get right with a mature library. Nothing else in
this repo needs it - saml-hud.sh itself is stdlib only.

    python3 tools/make_samples.py
"""

from __future__ import annotations

import base64
import datetime
import json
import os
import shutil
import sys
import urllib.parse
import zlib

try:
    from samlx.crypto_ops import (
        encrypt_xml_assertion,
        generate_self_signed_keypair,
        sign_saml_xml,
    )
    from samlx.encoder import build_redirect_url, encode_post_base64
except ImportError:  # pragma: no cover
    sys.exit("samlx helper package not found - run: pip install -e ../samlx")


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "samples")
IDP_CN = "idp.kali-lab.local"
SP_CN = "sp.kali-lab.local"
ACS = "https://sp.kali-lab.local/saml/acs"
AUDIENCE = "https://sp.kali-lab.local/metadata"


def stamp(minutes: int) -> str:
    return (datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")


def response_xml(*, nameid: str = "elliot@kali-lab.local") -> str:
    now = stamp(0)
    return f"""<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" \
xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp_9f82a1c4d7" Version="2.0" \
IssueInstant="{now}" Destination="{ACS}" InResponseTo="_req_4412ab">
  <saml:Issuer>https://{IDP_CN}/metadata</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion ID="_assn_77b31e90aa" Version="2.0" IssueInstant="{now}">
    <saml:Issuer>https://{IDP_CN}/metadata</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{nameid}</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData InResponseTo="_req_4412ab" NotOnOrAfter="{stamp(10)}" Recipient="{ACS}"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="{stamp(-1)}" NotOnOrAfter="{stamp(10)}">
      <saml:AudienceRestriction>
        <saml:Audience>{AUDIENCE}</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="{now}" SessionIndex="_sess_9001">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute Name="email" FriendlyName="Email Address">
        <saml:AttributeValue>{nameid}</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="role" FriendlyName="Security Role">
        <saml:AttributeValue>SecurityAnalyst</saml:AttributeValue>
        <saml:AttributeValue>SSOAdmin</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="department" FriendlyName="Department">
        <saml:AttributeValue>OffensiveSecurity</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>"""


def authn_request_xml() -> str:
    return f"""<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" \
xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_req_4412ab" Version="2.0" \
IssueInstant="{stamp(0)}" Destination="https://{IDP_CN}/sso/redirect" \
AssertionConsumerServiceURL="{ACS}" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
  <saml:Issuer>https://{SP_CN}/metadata</saml:Issuer>
  <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" AllowCreate="true"/>
</samlp:AuthnRequest>"""


def main() -> None:
    os.makedirs(OUT, exist_ok=True)

    idp_key, idp_cert = generate_self_signed_keypair(IDP_CN)
    sp_key, sp_cert = generate_self_signed_keypair(SP_CN)
    for name, blob in (("idp_cert.pem", idp_cert), ("sp_cert.pem", sp_cert),
                       ("sp_private.pem", sp_key)):
        with open(os.path.join(OUT, name), "w") as fh:
            fh.write(blob)

    # --- signed response (response + assertion signatures)
    signed = sign_saml_xml(response_xml(), idp_key, idp_cert, target="both")
    with open(os.path.join(OUT, "signed_response.b64"), "w") as fh:
        fh.write(encode_post_base64(signed))

    # --- tampered twin: same signatures, one claim edited (must fail verification)
    tampered = signed.replace("elliot@kali-lab.local", "admin@kali-lab.local")
    with open(os.path.join(OUT, "tampered_response.b64"), "w") as fh:
        fh.write(encode_post_base64(tampered))

    # --- encrypted assertion (outer response signed, assertion AES encrypted)
    encrypted = encrypt_xml_assertion(signed, sp_cert, data_alg="aes256-cbc")
    with open(os.path.join(OUT, "encrypted_response.xml"), "w") as fh:
        fh.write(encrypted)

    # --- HTTP-Redirect AuthnRequest with a §3.4.4.1 query signature
    with open(os.path.join(OUT, "redirect_authn.url"), "w") as fh:
        fh.write(build_redirect_url(
            authn_request_xml(), f"https://{IDP_CN}/sso/redirect",
            param_name="SAMLRequest", relay_state="/dashboard/admin",
            key_input=sp_key, sig_alg="rsa-sha256",
        ))

    # --- Burp/ZAP style raw request capture
    body = "SAMLResponse=" + urllib.parse.quote(encode_post_base64(signed), safe="")
    with open(os.path.join(OUT, "burp_capture.http"), "w") as fh:
        fh.write(
            f"POST /saml/acs HTTP/1.1\nHost: sp.kali-lab.local\n"
            f"User-Agent: Mozilla/5.0 (X11; Linux x86_64) BurpSuite\n"
            f"Content-Type: application/x-www-form-urlencoded\n"
            f"Content-Length: {len(body)}\n\n{body}\n"
        )

    # --- minimal multi-hop HAR capture (redirect hop + POST hop)
    redirect_url = open(os.path.join(OUT, "redirect_authn.url")).read().strip()
    har = {"log": {"version": "1.2", "creator": {"name": "saml-hud", "version": "2.0"},
                   "entries": [
                       {"startedDateTime": stamp(0), "time": 42,
                        "request": {"method": "GET", "url": redirect_url,
                                    "headers": [], "queryString": []},
                        "response": {"status": 302, "content": {"text": ""}}},
                       {"startedDateTime": stamp(0), "time": 88,
                        "request": {"method": "POST", "url": ACS, "headers": [],
                                    "postData": {"mimeType": "application/x-www-form-urlencoded",
                                                 "text": body}},
                        "response": {"status": 200, "content": {"text": "OK"}}},
                   ]}}
    with open(os.path.join(OUT, "sso_trace.har"), "w") as fh:
        json.dump(har, fh, indent=2)

    print(f"samples written to {OUT}")


if __name__ == "__main__":
    main()
