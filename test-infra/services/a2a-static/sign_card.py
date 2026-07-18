"""Build conformant current and legacy A2A cards plus a trusted JWKS.

The current v1 Agent Card is signed with a real ES256 AgentCardSignature over
its JCS-canonical proto-JSON representation. The legacy v0.3 card is a separate
conformant deployment used solely to exercise the standardized fallback path.
The public key is served separately and is trusted out of band by the offline
test runner; card-controlled key material is intentionally not used.
"""

import json
import sys

from jwcrypto import jwk, jws

KID = "a2a-static-es256"
def canonical(obj):
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def build_current_card():
    # Every required proto field is present and every included optional field
    # is non-default, so this object is already its proto-JSON presence form.
    return {
        "name": "PayrollAgent",
        "description": "Enterprise payroll automation agent with a statically hosted, signed current Agent Card.",
        "supportedInterfaces": [
            {
                "url": "http://a2a-static/a2a",
                "protocolBinding": "JSONRPC",
                "protocolVersion": "1.0",
            }
        ],
        "version": "2.1.0",
        "provider": {"organization": "AcmeCorp", "url": "https://acme.example"},
        "capabilities": {"streaming": True},
        "defaultInputModes": ["application/json"],
        "defaultOutputModes": ["application/json"],
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
    }


def build_legacy_card():
    return {
        "name": "LegacyArchiveAgent",
        "description": "Legacy payroll archive agent served from the standard fallback location.",
        "url": "http://a2a-static/legacy/a2a",
        "version": "0.3.0",
        "provider": {"organization": "AcmeCorp", "url": "https://acme.example"},
        "protocolVersion": "0.3.0",
        "preferredTransport": "JSONRPC",
        "capabilities": {},
        "defaultInputModes": ["application/json"],
        "defaultOutputModes": ["application/json"],
        "skills": [
            {
                "id": "archive-payslip",
                "name": "ArchivePayslip",
                "description": "Archive a payroll payslip in the legacy records system.",
                "tags": ["payroll", "archive"],
            }
        ],
    }


def main(pem_path, out_current, out_legacy, out_jwks):
    with open(pem_path, "rb") as fh:
        key = jwk.JWK.from_pem(fh.read())
    key["kid"] = KID
    key["alg"] = "ES256"
    key["use"] = "sig"

    public_jwk = json.loads(key.export_public())
    card = build_current_card()

    payload = canonical(card)
    token = jws.JWS(payload)
    token.add_signature(
        key,
        alg="ES256",
        protected=json.dumps({"alg": "ES256", "kid": KID}),
    )
    protected_seg, _payload_seg, signature_seg = token.serialize(compact=True).split(".")
    card["signatures"] = [{"protected": protected_seg, "signature": signature_seg}]

    with open(out_current, "w") as fh:
        json.dump(card, fh, indent=2)
        fh.write("\n")
    with open(out_legacy, "w") as fh:
        json.dump(build_legacy_card(), fh, indent=2)
        fh.write("\n")
    with open(out_jwks, "w") as fh:
        json.dump({"keys": [public_jwk]}, fh, indent=2)
        fh.write("\n")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
