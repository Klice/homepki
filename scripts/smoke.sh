#!/usr/bin/env bash
# End-to-end smoke test for homepki: builds the binary, runs setup → unlock →
# issue chain → exercise every download endpoint → tear down. Asserts response
# headers, status codes, and that the bytes round-trip through openssl.
#
# Idempotent: each run uses a fresh temp data dir and a fresh server process.
# Exits non-zero on the first failed assertion.
#
# Usage:
#   scripts/smoke.sh                 # use defaults
#   PORT=19090 scripts/smoke.sh      # pick a different port

set -euo pipefail

PORT="${PORT:-18080}"
PASSPHRASE="${PASSPHRASE:-smoke-test-passphrase-12345}"
BASE_URL="http://localhost:${PORT}"

WORK_DIR="$(mktemp -d -t homepki-smoke.XXXXXX)"
COOKIES="${WORK_DIR}/cookies.txt"
SERVER_LOG="${WORK_DIR}/server.log"
SERVER_PID=""

# ---- bookkeeping -----------------------------------------------------------

PASSED=0
FAILED=0
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cleanup() {
    if [[ -n "${SERVER_PID}" ]] && kill -0 "${SERVER_PID}" 2>/dev/null; then
        kill "${SERVER_PID}" 2>/dev/null || true
        wait "${SERVER_PID}" 2>/dev/null || true
    fi
    if [[ "${KEEP_TMPDIR:-0}" != "1" ]]; then
        rm -rf "${WORK_DIR}"
    else
        echo "  (kept tmpdir: ${WORK_DIR})"
    fi
}
trap cleanup EXIT

pass() { echo "  ok    $1"; PASSED=$((PASSED + 1)); }
fail() { echo "  FAIL  $1"; FAILED=$((FAILED + 1)); }

# assert_eq <label> <actual> <expected>
assert_eq() {
    if [[ "$2" == "$3" ]]; then pass "$1"; else fail "$1: got '$2', want '$3'"; fi
}

# assert_contains <label> <haystack> <needle>
assert_contains() {
    if [[ "$2" == *"$3"* ]]; then pass "$1"; else fail "$1: '$2' missing '$3'"; fi
}

# ---- server lifecycle ------------------------------------------------------

start_server() {
    echo "==> Building homepki"
    (cd "${PROJECT_ROOT}" && go build -o "${WORK_DIR}/homepki" ./cmd/homepki)

    echo "==> Starting server on :${PORT} (data dir ${WORK_DIR}/data)"
    mkdir -p "${WORK_DIR}/data"
    CRL_BASE_URL="${BASE_URL}" \
    CM_DATA_DIR="${WORK_DIR}/data" \
    CM_LISTEN_ADDR=":${PORT}" \
    CM_LOG_FORMAT=text \
    "${WORK_DIR}/homepki" >"${SERVER_LOG}" 2>&1 &
    SERVER_PID=$!

    # Wait for /healthz to come up (max ~10s).
    for _ in {1..50}; do
        if curl -sf "${BASE_URL}/healthz" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.2
    done
    echo "Server failed to start. Log:" >&2
    cat "${SERVER_LOG}" >&2
    return 1
}

# ---- helpers ---------------------------------------------------------------

# extract_attr <attr_name> <html_file>: pulls the value of an input named
# attr_name, or echoes empty string when not present. Decodes the few HTML
# entities html/template emits inside attribute values.
extract_attr() {
    local name="$1" file="$2"
    local match
    match=$(grep -oE "name=\"${name}\" value=\"[^\"]+\"" "${file}" | head -1) || true
    [[ -z "${match}" ]] && return 0
    printf '%s' "${match}" \
        | sed -E "s/.*value=\"([^\"]+)\".*/\1/" \
        | sed 's/&#43;/+/g; s/&amp;/\&/g'
}

# get_page <path> <out_html>
get_page() {
    curl -s -b "${COOKIES}" -c "${COOKIES}" -o "$2" "${BASE_URL}$1"
}

# post_form <path> <out_status_var> <out_location_var> <key=value...>
# Captures status and Location header into the named variables.
post_form() {
    local path="$1" out_status="$2" out_loc="$3"; shift 3
    local args=()
    for kv in "$@"; do args+=(--data-urlencode "$kv"); done
    local resp
    resp=$(curl -s -b "${COOKIES}" -c "${COOKIES}" -X POST -e "${BASE_URL}${path}" \
                "${args[@]}" -o /dev/null \
                -w "%{http_code}|%header{location}" "${BASE_URL}${path}")
    printf -v "${out_status}" "%s" "${resp%%|*}"
    printf -v "${out_loc}" "%s" "${resp#*|}"
}

# submit_form <path> [extra_form_args...]
# Fetches the form, copies csrf+form_token into the POST, asserts a 303 and
# echoes the resulting Location.
submit_form() {
    local path="$1"; shift
    local html="${WORK_DIR}/form.html"
    get_page "${path}" "${html}"
    local csrf form_token status loc
    csrf=$(extract_attr csrf_token "${html}")
    form_token=$(extract_attr form_token "${html}")
    post_form "${path}" status loc "csrf_token=${csrf}" "form_token=${form_token}" "$@"
    if [[ "${status}" != "303" ]]; then
        echo "submit_form ${path}: expected 303, got ${status}" >&2
        return 1
    fi
    echo "${loc}"
}

# get_status <path>: GET path, echo HTTP status code.
get_status() {
    curl -s -b "${COOKIES}" -o /dev/null -w "%{http_code}" "${BASE_URL}$1"
}

# get_headers <path> <out_file>: GET path, save headers + body to <out_file>.
# Echoes status code on stdout.
get_with_headers() {
    curl -s -b "${COOKIES}" -D "${WORK_DIR}/headers.txt" -o "$2" \
         -w "%{http_code}" "${BASE_URL}$1"
}

# header_value <name>: look up a header in the most recent get_with_headers.
header_value() {
    grep -i "^$1:" "${WORK_DIR}/headers.txt" | head -1 | sed -E "s/^[^:]+:\s*//I" | tr -d '\r'
}

# ---- the actual smoke flow -------------------------------------------------

bootstrap() {
    echo "==> Setup"
    local html="${WORK_DIR}/setup.html"
    get_page /setup "${html}"
    local csrf form_token status loc
    csrf=$(extract_attr csrf_token "${html}")
    form_token=$(extract_attr form_token "${html}")
    post_form /setup status loc \
        "csrf_token=${csrf}" "form_token=${form_token}" \
        "passphrase=${PASSPHRASE}" "passphrase2=${PASSPHRASE}"
    assert_eq "/setup → 303" "${status}" "303"
    assert_eq "/setup Location" "${loc}" "/"
}

issue_chain() {
    echo "==> Issuing root → intermediate → leaf"
    local loc

    loc=$(submit_form /certs/new/root \
        "subject_cn=Smoke-Root" "key_algo=ecdsa" "key_algo_params=P-256" "validity_days=3650")
    ROOT_ID="${loc#/certs/}"
    pass "issued root ${ROOT_ID}"

    loc=$(submit_form /certs/new/intermediate \
        "parent_id=${ROOT_ID}" "subject_cn=Smoke-Intermediate" \
        "key_algo=ecdsa" "key_algo_params=P-256" "validity_days=1825")
    INTER_ID="${loc#/certs/}"
    pass "issued intermediate ${INTER_ID}"

    loc=$(submit_form /certs/new/leaf \
        "parent_id=${INTER_ID}" "subject_cn=smoke.leaf.test" \
        "key_algo=ecdsa" "key_algo_params=P-256" \
        "san_dns=smoke.leaf.test" "validity_days=90")
    LEAF_ID="${loc#/certs/}"
    pass "issued leaf ${LEAF_ID}"
}

test_cert_pem() {
    echo "==> GET /certs/{leaf}/cert.pem"
    local status
    status=$(get_with_headers "/certs/${LEAF_ID}/cert.pem" "${WORK_DIR}/leaf.crt")
    assert_eq "status" "${status}" "200"
    assert_eq "Content-Type" "$(header_value content-type)" "application/x-pem-file"
    assert_contains "Cache-Control non-sensitive" "$(header_value cache-control)" "private"
    assert_contains "Content-Disposition .crt" "$(header_value content-disposition)" "smoke.leaf.test.crt"

    local subj
    subj=$(openssl x509 -in "${WORK_DIR}/leaf.crt" -noout -subject 2>&1)
    assert_contains "openssl parses cert" "${subj}" "smoke.leaf.test"
}

test_key_pem() {
    echo "==> GET /certs/{leaf}/key.pem"
    local status
    status=$(get_with_headers "/certs/${LEAF_ID}/key.pem" "${WORK_DIR}/leaf.key")
    assert_eq "status" "${status}" "200"
    assert_contains "Cache-Control sensitive" "$(header_value cache-control)" "no-store"
    assert_eq "Pragma" "$(header_value pragma)" "no-cache"
    assert_contains "Content-Disposition .key" "$(header_value content-disposition)" "smoke.leaf.test.key"

    if openssl pkey -in "${WORK_DIR}/leaf.key" -noout 2>/dev/null; then
        pass "openssl parses pkcs8 key"
    else
        fail "openssl pkey: failed to parse key.pem"
    fi
}

test_chain_pem() {
    echo "==> GET /certs/{*}/chain.pem"
    local status
    status=$(get_with_headers "/certs/${LEAF_ID}/chain.pem" "${WORK_DIR}/chain.crt")
    assert_eq "leaf status" "${status}" "200"
    local count
    count=$(grep -c -- "-----BEGIN CERTIFICATE-----" "${WORK_DIR}/chain.crt" || true)
    assert_eq "leaf chain block count" "${count}" "1"
    local subj
    subj=$(openssl x509 -in "${WORK_DIR}/chain.crt" -noout -subject 2>&1)
    assert_contains "leaf chain[0] is intermediate" "${subj}" "Smoke-Intermediate"

    assert_eq "root chain → 404" "$(get_status "/certs/${ROOT_ID}/chain.pem")" "404"
}

test_fullchain_pem() {
    echo "==> GET /certs/{*}/fullchain.pem"
    local status
    status=$(get_with_headers "/certs/${LEAF_ID}/fullchain.pem" "${WORK_DIR}/fullchain.crt")
    assert_eq "leaf status" "${status}" "200"
    local count
    count=$(grep -c -- "-----BEGIN CERTIFICATE-----" "${WORK_DIR}/fullchain.crt" || true)
    assert_eq "leaf fullchain block count (leaf+intermediate)" "${count}" "2"

    assert_eq "intermediate fullchain → 404" "$(get_status "/certs/${INTER_ID}/fullchain.pem")" "404"
    assert_eq "root fullchain → 404"         "$(get_status "/certs/${ROOT_ID}/fullchain.pem")"  "404"
}

test_openssl_verify() {
    echo "==> openssl verify leaf via chain + root"
    get_with_headers "/certs/${ROOT_ID}/cert.pem" "${WORK_DIR}/root.crt" >/dev/null
    if openssl verify -CAfile "${WORK_DIR}/root.crt" -untrusted "${WORK_DIR}/chain.crt" "${WORK_DIR}/leaf.crt" >/dev/null 2>&1; then
        pass "openssl verify"
    else
        fail "openssl verify: leaf does not chain to root"
    fi
}

test_bundle_p12() {
    echo "==> POST /certs/{leaf}/bundle.p12"
    # Need a CSRF token from a recently-rendered page on this cert.
    get_page "/certs/${LEAF_ID}" "${WORK_DIR}/leaf-detail.html"
    local csrf status loc
    csrf=$(extract_attr csrf_token "${WORK_DIR}/leaf-detail.html")

    # Happy path with password.
    status=$(curl -s -b "${COOKIES}" -D "${WORK_DIR}/headers.txt" \
                  -X POST -e "${BASE_URL}/certs/${LEAF_ID}" \
                  --data-urlencode "csrf_token=${csrf}" \
                  --data-urlencode "password=hunter2" \
                  -o "${WORK_DIR}/bundle.p12" \
                  -w "%{http_code}" "${BASE_URL}/certs/${LEAF_ID}/bundle.p12")
    assert_eq "status" "${status}" "200"
    assert_eq "Content-Type" "$(header_value content-type)" "application/x-pkcs12"
    assert_contains "Cache-Control sensitive" "$(header_value cache-control)" "no-store"

    # Decode round-trip: extract every cert's subject line from the bundle.
    local subjects
    subjects=$(openssl pkcs12 -in "${WORK_DIR}/bundle.p12" -nokeys -passin pass:hunter2 2>/dev/null \
        | grep -E "^subject=" || true)
    assert_contains "p12 contains leaf" "${subjects}" "smoke.leaf.test"
    assert_contains "p12 contains intermediate" "${subjects}" "Smoke-Intermediate"

    # Wrong password fails openssl decode.
    if openssl pkcs12 -in "${WORK_DIR}/bundle.p12" -nokeys -passin pass:wrong -noout >/dev/null 2>&1; then
        fail "p12 decoded with wrong password"
    else
        pass "p12 rejects wrong password"
    fi

    # Missing password → 400.
    local bad_status bad_loc
    post_form "/certs/${LEAF_ID}/bundle.p12" bad_status bad_loc "csrf_token=${csrf}"
    assert_eq "missing password → 400" "${bad_status}" "400"

    # Non-leaf → 404.
    local non_status non_loc
    post_form "/certs/${INTER_ID}/bundle.p12" non_status non_loc \
        "csrf_token=${csrf}" "password=hunter2"
    assert_eq "intermediate p12 → 404" "${non_status}" "404"
}

test_deploy() {
    echo "==> Deploy: create + run + edit + delete"
    local out_dir="${WORK_DIR}/deploy-out"
    mkdir -p "${out_dir}"

    local cert_path="${out_dir}/leaf.crt"
    local key_path="${out_dir}/leaf.key"
    local chain_path="${out_dir}/leaf-fullchain.crt"
    local flag="${out_dir}/post-ran"

    # Create a deploy target via the form-token gated endpoint.
    local html="${WORK_DIR}/deploy-new.html"
    get_page "/certs/${LEAF_ID}/deploy/new" "${html}"
    local csrf form_token status loc
    csrf=$(extract_attr csrf_token "${html}")
    form_token=$(extract_attr form_token "${html}")
    post_form "/certs/${LEAF_ID}/deploy/new" status loc \
        "csrf_token=${csrf}" "form_token=${form_token}" \
        "name=smoke-target" \
        "cert_path=${cert_path}" \
        "key_path=${key_path}" \
        "chain_path=${chain_path}" \
        "mode=0644" \
        "post_command=touch ${flag}" \
        "auto_on_rotate=1"
    assert_eq "create → 303" "${status}" "303"
    assert_eq "create Location" "${loc}" "/certs/${LEAF_ID}"

    # Detail page now lists the target.
    get_page "/certs/${LEAF_ID}" "${WORK_DIR}/leaf-detail.html"
    local body
    body=$(cat "${WORK_DIR}/leaf-detail.html")
    assert_contains "detail lists target name" "${body}" "smoke-target"
    assert_contains "detail lists cert_path" "${body}" "${cert_path}"

    # Pull the new target id straight out of the rendered links so we can
    # POST run / edit / delete without hitting the DB.
    local TID
    TID=$(printf '%s' "${body}" | grep -oE "/certs/${LEAF_ID}/deploy/[a-f0-9-]+/run" | head -1 \
          | sed -E "s|/certs/${LEAF_ID}/deploy/([a-f0-9-]+)/run|\1|")
    if [[ -z "${TID}" ]]; then
        fail "could not extract deploy target id from detail page"
        return
    fi
    pass "extracted target id ${TID}"

    # Run the target.
    csrf=$(extract_attr csrf_token "${WORK_DIR}/leaf-detail.html")
    post_form "/certs/${LEAF_ID}/deploy/${TID}/run" status loc "csrf_token=${csrf}"
    assert_eq "run → 303" "${status}" "303"

    # Files exist with expected mode and parse cleanly.
    if openssl x509 -in "${cert_path}" -noout -subject 2>/dev/null | grep -q "smoke.leaf.test"; then
        pass "deployed cert.pem parses + matches CN"
    else
        fail "deployed cert.pem does not parse / wrong CN"
    fi
    if openssl pkey -in "${key_path}" -noout 2>/dev/null; then
        pass "deployed key.pem parses"
    else
        fail "deployed key.pem does not parse"
    fi
    local block_count
    block_count=$(grep -c -- "-----BEGIN CERTIFICATE-----" "${chain_path}" || true)
    assert_eq "deployed fullchain block count" "${block_count}" "2"

    # Mode is 0644 (we set it on create).
    if [[ "$(stat -c '%a' "${cert_path}")" == "644" ]]; then
        pass "cert mode is 644"
    else
        fail "cert mode: got $(stat -c '%a' "${cert_path}"), want 644"
    fi

    # post_command ran.
    if [[ -e "${flag}" ]]; then
        pass "post_command ran"
    else
        fail "post_command did not run"
    fi

    # Detail page shows status pill = ok.
    get_page "/certs/${LEAF_ID}" "${WORK_DIR}/leaf-detail.html"
    if grep -qE 'pill[^"]*pill-ok[^>]*>ok' "${WORK_DIR}/leaf-detail.html"; then
        pass "detail shows ok pill for target"
    else
        fail "detail does not show ok pill (target likely failed)"
    fi

    # Run-all also works (one target → still ok).
    csrf=$(extract_attr csrf_token "${WORK_DIR}/leaf-detail.html")
    post_form "/certs/${LEAF_ID}/deploy" status loc "csrf_token=${csrf}"
    assert_eq "run-all → 303" "${status}" "303"

    # Delete the target (idempotent).
    post_form "/certs/${LEAF_ID}/deploy/${TID}/delete" status loc "csrf_token=${csrf}"
    assert_eq "delete → 303" "${status}" "303"
    post_form "/certs/${LEAF_ID}/deploy/${TID}/delete" status loc "csrf_token=${csrf}"
    assert_eq "delete replay → 303 (idempotent)" "${status}" "303"
    get_page "/certs/${LEAF_ID}" "${WORK_DIR}/leaf-detail.html"
    if grep -q "smoke-target" "${WORK_DIR}/leaf-detail.html"; then
        fail "deleted target still shown on detail page"
    else
        pass "target removed from detail page"
    fi
}

test_lock_state() {
    echo "==> Lock and re-check sensitive endpoints"
    local csrf status loc
    get_page "/certs/${LEAF_ID}" "${WORK_DIR}/leaf-detail.html"
    csrf=$(extract_attr csrf_token "${WORK_DIR}/leaf-detail.html")
    post_form "/lock" status loc "csrf_token=${csrf}"
    assert_eq "/lock → 303" "${status}" "303"

    # Locked downloads redirect to /unlock per the existing requireUnlocked
    # gate. (The spec describes 423 here; the codebase consistently 303s.)
    assert_eq "cert.pem when locked → 303" "$(get_status "/certs/${LEAF_ID}/cert.pem")" "303"
    assert_eq "key.pem when locked → 303"  "$(get_status "/certs/${LEAF_ID}/key.pem")"  "303"
}

# ---- entry point -----------------------------------------------------------

main() {
    start_server
    bootstrap
    issue_chain
    test_cert_pem
    test_key_pem
    test_chain_pem
    test_fullchain_pem
    test_openssl_verify
    test_bundle_p12
    test_deploy
    test_lock_state

    echo
    echo "==> Result: ${PASSED} passed, ${FAILED} failed"
    if [[ "${FAILED}" -gt 0 ]]; then
        echo "Server log: ${SERVER_LOG}"
        if [[ "${KEEP_TMPDIR:-0}" != "1" ]]; then
            cat "${SERVER_LOG}"
        fi
        exit 1
    fi
}

main "$@"
