#!/usr/bin/env python3
"""Idempotently create the LiteLLM virtual-key fixture."""

import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request


BASE_URL = os.environ.get("LITELLM_URL", "http://litellm:4000").rstrip("/")
MASTER_KEY = os.environ["LITELLM_MASTER_KEY"]
KEY_ALIAS = "agenthound-offline-fixture"
MODELS = [
    "agenthound-openai-placeholder",
    "agenthound-anthropic-placeholder",
]


def request_json(path: str, method: str = "GET", payload: dict | None = None) -> dict:
    body = None
    headers = {"Authorization": f"Bearer {MASTER_KEY}"}
    if payload is not None:
        body = json.dumps(payload).encode()
        headers["Content-Type"] = "application/json"

    request = urllib.request.Request(
        f"{BASE_URL}{path}",
        data=body,
        headers=headers,
        method=method,
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        detail = error.read().decode(errors="replace")
        raise RuntimeError(
            f"{method} {path} returned HTTP {error.code}: {detail}"
        ) from error


def fixture_keys() -> list[dict]:
    query = urllib.parse.urlencode(
        {
            "key_alias": KEY_ALIAS,
            "return_full_object": "true",
            "page": 1,
            "size": 100,
        }
    )
    response = request_json(f"/key/list?{query}")
    keys = response.get("keys")
    if not isinstance(keys, list):
        raise RuntimeError(f"/key/list returned an invalid keys field: {keys!r}")
    return keys


def validate_model_info() -> None:
    response = request_json("/model/info")
    entries = response.get("data")
    if not isinstance(entries, list):
        raise RuntimeError("/model/info returned no data array")

    model_names = {
        entry.get("model_name") for entry in entries if isinstance(entry, dict)
    }
    missing = set(MODELS) - model_names
    if missing:
        raise RuntimeError(f"/model/info is missing fixture models: {sorted(missing)}")


def validate_key(key: dict) -> None:
    if not isinstance(key, dict) or key.get("key_alias") != KEY_ALIAS:
        raise RuntimeError(f"/key/list returned an unexpected fixture key: {key!r}")

    token = key.get("token")
    if not isinstance(token, str) or re.fullmatch(r"[0-9a-f]{64}", token) is None:
        raise RuntimeError("/key/list did not expose the stored SHA-256 token")

    key_models = key.get("models")
    if not isinstance(key_models, list) or not set(MODELS).issubset(key_models):
        raise RuntimeError(f"fixture key has unexpected models: {key_models!r}")


def main() -> None:
    validate_model_info()

    keys = fixture_keys()
    created = False
    if not keys:
        request_json(
            "/key/generate",
            method="POST",
            payload={
                "key_alias": KEY_ALIAS,
                "models": MODELS,
                "max_budget": 5,
                "metadata": {
                    "fixture": "agenthound-offline-collector",
                    "purpose": "virtual-key loot coverage",
                },
            },
        )
        keys = fixture_keys()
        created = True

    if len(keys) != 1:
        raise RuntimeError(
            f"expected exactly one {KEY_ALIAS!r} key, found {len(keys)}"
        )
    validate_key(keys[0])

    action = "created" if created else "reused"
    print(f"{action} LiteLLM virtual key alias {KEY_ALIAS}")


if __name__ == "__main__":
    main()
