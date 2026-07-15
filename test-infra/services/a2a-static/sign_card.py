"""Reproducibly build a genuinely JWS-signed A2A v0.3.0 agent card + JWKS.

The signature is a real ES256 JWS (no fabricated bytes). It is produced in the
flattened AgentCardSignature object form `{protected, signature}` mandated by
the A2A spec (section 8.4): the signature covers the JCS-canonical agent card
with the `signatures` member removed. AgentHound's verifier
(modules/a2a/jws.go: canonicalSignedPayload) reconstructs that same canonical
payload by re-serializing the parsed card with Go's encoding/json (sorted keys,
no insignificant whitespace, HTML-escaping disabled). Python's
`json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`
is byte-identical to that output for ASCII-only, number-free card content, so
the signature verifies as `verified` against the real collector.

The public key is embedded inline as `jwks` (offline-verifiable, deterministic)
and also served at /.well-known/jwks.json; `jwks_uri` and the signature's `jku`
header advertise that endpoint for spec-compliant remote key resolution.
"""

import json
import sys

from jwcrypto import jwk, jws

KID = "a2a-static-es256"
JWKS_URL = "http://a2a-static/.well-known/jwks.json"


def canonical(obj):
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def build_card(public_jwk):
    # A2A v0.3.0 (legacy) card: top-level `url` + string `protocolVersion`, no
    # `supportedInterfaces`. AgentHound classifies this as v0.3.0 and drives its
    # legacy parse path (modules/a2a/parse.go: parseV030).
    return {
        "name": "PayrollAgent",
        "description": "Enterprise payroll automation agent (statically hosted, signed card).",
        "url": "http://a2a-static/a2a",
        "version": "2.1.0",
        "provider": {"organization": "AcmeCorp"},
        "protocolVersion": "0.3.0",
        "capabilities": {"streaming": True, "pushNotifications": True},
        "securitySchemes": {
            "corp_oauth": {
                "type": "oauth2",
                "flows": {
                    "clientCredentials": {
                        "tokenUrl": "http://a2a-static/oauth/token",
                        "scopes": {
                            "payroll.read": "Read payroll",
                            "payroll.write": "Write payroll",
                        },
                    }
                },
            }
        },
        "security": [{"corp_oauth": ["payroll.read"]}],
        "skills": [
            {
                "id": "run-payroll",
                "name": "RunPayroll",
                "description": "Execute a payroll run for a pay period.",
                "tags": ["payroll", "finance"],
                "inputModes": ["application/json"],
                "outputModes": ["application/json"],
            }
        ],
        "jwks": {"keys": [public_jwk]},
        "jwks_uri": JWKS_URL,
    }


def main(pem_path, out_card, out_jwks):
    with open(pem_path, "rb") as fh:
        key = jwk.JWK.from_pem(fh.read())
    key["kid"] = KID
    key["alg"] = "ES256"
    key["use"] = "sig"

    public_jwk = json.loads(key.export_public())
    card = build_card(public_jwk)

    payload = canonical(card)
    token = jws.JWS(payload)
    token.add_signature(
        key,
        alg="ES256",
        protected=json.dumps({"alg": "ES256", "kid": KID, "jku": JWKS_URL}),
    )
    protected_seg, _payload_seg, signature_seg = token.serialize(compact=True).split(".")
    card["signatures"] = [{"protected": protected_seg, "signature": signature_seg}]

    with open(out_card, "w") as fh:
        json.dump(card, fh, indent=2)
        fh.write("\n")
    with open(out_jwks, "w") as fh:
        json.dump({"keys": [public_jwk]}, fh, indent=2)
        fh.write("\n")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2], sys.argv[3])
