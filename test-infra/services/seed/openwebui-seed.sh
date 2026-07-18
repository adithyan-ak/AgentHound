#!/bin/sh
set -eu

base=http://openwebui:3000
runtime=/root/fixtures/runtime.json
email=admin@agenthound.invalid
password='Harness-OpenWebUI-Password-2026!'

body="$(jq -nc --arg email "${email}" --arg password "${password}" \
  '{name:"AgentHound Harness Admin",email:$email,password:$password,profile_image_url:""}')"
response="$(curl -sS -X POST -H 'Content-Type: application/json' --data "${body}" "${base}/api/v1/auths/signup")"
token="$(printf '%s' "${response}" | jq -r '.token // empty')"
if [ -z "${token}" ]; then
  body="$(jq -nc --arg email "${email}" --arg password "${password}" \
    '{email:$email,password:$password}')"
  response="$(curl -fsS -X POST -H 'Content-Type: application/json' --data "${body}" "${base}/api/v1/auths/signin")"
  token="$(printf '%s' "${response}" | jq -er '.token')"
fi

jq --arg token "${token}" '.openwebui = {token:$token}' "${runtime}" >"${runtime}.tmp"
mv "${runtime}.tmp" "${runtime}"
printf 'Seeded Open WebUI admin through its public signup/signin API.\n'
