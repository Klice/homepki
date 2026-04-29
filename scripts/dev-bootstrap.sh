#!/usr/bin/env bash
# scripts/dev-bootstrap.sh — wipe the local data dir, start a fresh
# homepki server, run first-run setup, and issue a realistic chain of
# CAs and leaf certs so the UI has something to look at.
#
# Idempotent: re-running kills any previous dev server (via pidfile),
# blows away ./tmp/data, and starts over.
#
# Usage:
#   scripts/dev-bootstrap.sh
#   PORT=18080 scripts/dev-bootstrap.sh
#   PASSPHRASE='something else' scripts/dev-bootstrap.sh
#
# After the script finishes the server is left running in the background.
# To stop it later:
#   kill "$(cat tmp/homepki.pid)"
# Or just re-run the script — it'll restart cleanly.

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${PROJECT_ROOT}"

PORT="${PORT:-8080}"
PASSPHRASE="${PASSPHRASE:-dev-passphrase-12345}"
DATA_DIR="${DATA_DIR:-./tmp/data}"
PIDFILE="${PIDFILE:-./tmp/homepki.pid}"
LOGFILE="${LOGFILE:-./tmp/homepki.log}"
BASE_URL="http://localhost:${PORT}"

# ---- helpers ---------------------------------------------------------------

log()  { printf '\033[36m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[33m!!  %s\033[0m\n' "$*" >&2; }
die()  { printf '\033[31mERR %s\033[0m\n' "$*" >&2; exit 1; }

extract_attr() {
    # extract_attr <name> <html_file> — pulls value="..." for input named
    # <name>; decodes the HTML entities html/template emits in attributes.
    local name="$1" file="$2" match
    match=$(grep -oE "name=\"${name}\" value=\"[^\"]+\"" "${file}" | head -1) || true
    [[ -z "${match}" ]] && return 0
    printf '%s' "${match}" \
        | sed -E "s/.*value=\"([^\"]+)\".*/\1/" \
        | sed 's/&#43;/+/g; s/&amp;/\&/g'
}

cookies="$(mktemp -t homepki-cookies.XXXXXX)"
trap 'rm -f "${cookies}"' EXIT

get_page() { curl -fs -b "${cookies}" -c "${cookies}" -o "$2" "${BASE_URL}$1"; }

post_form() {
    # post_form <path> <key=val...> — posts via the cookie jar; echoes the
    # 303 Location header on success, exits non-zero on any other status.
    local path="$1"; shift
    local args=()
    for kv in "$@"; do args+=(--data-urlencode "$kv"); done
    local resp status loc
    resp=$(curl -s -b "${cookies}" -c "${cookies}" -X POST -e "${BASE_URL}${path}" \
                "${args[@]}" -o /dev/null \
                -w "%{http_code}|%header{location}" "${BASE_URL}${path}")
    status="${resp%%|*}"
    loc="${resp#*|}"
    if [[ "${status}" != "303" ]]; then
        die "POST ${path}: expected 303, got ${status}"
    fi
    printf '%s' "${loc}"
}

submit_form() {
    # submit_form <path> <field=val...> — fetches the form (to grab CSRF
    # cookie + form_token), POSTs, returns the resulting Location.
    local path="$1"; shift
    local html
    html=$(mktemp -t homepki-form.XXXXXX)
    get_page "${path}" "${html}"
    local csrf form_token
    csrf=$(extract_attr csrf_token "${html}")
    form_token=$(extract_attr form_token "${html}")
    rm -f "${html}"
    post_form "${path}" "csrf_token=${csrf}" "form_token=${form_token}" "$@"
}

# ---- lifecycle -------------------------------------------------------------

stop_existing_server() {
    # 1. Kill the pidfile's process if it's still alive.
    if [[ -f "${PIDFILE}" ]]; then
        local pid
        pid=$(cat "${PIDFILE}")
        if kill -0 "${pid}" 2>/dev/null; then
            log "stopping previous dev server (pid ${pid})"
            kill "${pid}" 2>/dev/null || true
            wait "${pid}" 2>/dev/null || true
        fi
        rm -f "${PIDFILE}"
    fi

    # 2. Belt-and-suspenders: clear anything else holding ${PORT}. Stale
    #    processes from earlier crashed runs would otherwise answer
    #    /healthz from a different cookie domain than our fresh start,
    #    leading to confusing CSRF 403s on the first POST.
    if command -v lsof >/dev/null 2>&1; then
        local stale
        stale=$(lsof -ti "tcp:${PORT}" -sTCP:LISTEN 2>/dev/null || true)
        if [[ -n "${stale}" ]]; then
            warn "killing stale listeners on :${PORT}: ${stale}"
            # shellcheck disable=SC2086 — intentional word-splitting for multi-pid
            kill ${stale} 2>/dev/null || true
            sleep 0.5
            stale=$(lsof -ti "tcp:${PORT}" -sTCP:LISTEN 2>/dev/null || true)
            [[ -n "${stale}" ]] && kill -9 ${stale} 2>/dev/null || true
        fi
    fi
}

wipe_data() {
    log "wiping ${DATA_DIR}"
    rm -rf "${DATA_DIR}"
    mkdir -p "${DATA_DIR}" "$(dirname "${PIDFILE}")"
}

start_server() {
    log "starting fresh server on :${PORT}"
    CRL_BASE_URL="${BASE_URL}" \
    CM_LISTEN_ADDR=":${PORT}" \
    CM_DATA_DIR="${DATA_DIR}" \
    CM_LOG_FORMAT=text \
    go run ./cmd/homepki >"${LOGFILE}" 2>&1 &
    local pid=$!
    echo "${pid}" >"${PIDFILE}"

    for _ in {1..50}; do
        # If the process we just spawned has already exited (e.g., port
        # was still bound by a stale process and bind failed), bail out
        # with the server log instead of polling /healthz forever — a
        # stranger holding the port would happily answer 200 from there.
        if ! kill -0 "${pid}" 2>/dev/null; then
            warn "server log:"
            cat "${LOGFILE}" >&2
            die "spawned server process exited before /healthz came up"
        fi
        if curl -sf "${BASE_URL}/healthz" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.2
    done
    warn "server log:"
    cat "${LOGFILE}" >&2
    die "server failed to come up on ${BASE_URL}"
}

# ---- seeding ---------------------------------------------------------------

setup_passphrase() {
    log "running first-run setup"
    local html
    html=$(mktemp -t homepki-setup.XXXXXX)
    get_page /setup "${html}"
    local csrf form_token
    csrf=$(extract_attr csrf_token "${html}")
    form_token=$(extract_attr form_token "${html}")
    rm -f "${html}"
    post_form /setup \
        "csrf_token=${csrf}" "form_token=${form_token}" \
        "passphrase=${PASSPHRASE}" "passphrase2=${PASSPHRASE}" >/dev/null
}

issue_root() {
    # issue_root <CN> [validity_days]
    local cn="$1" days="${2:-3650}" loc
    loc=$(submit_form /certs/new/root \
        "subject_cn=${cn}" \
        "key_algo=ecdsa" "key_algo_params=P-256" \
        "validity_days=${days}")
    printf '%s' "${loc#/certs/}"
}

issue_intermediate() {
    # issue_intermediate <parent_id> <CN> [validity_days]
    local parent="$1" cn="$2" days="${3:-1825}" loc
    loc=$(submit_form /certs/new/intermediate \
        "parent_id=${parent}" "subject_cn=${cn}" \
        "key_algo=ecdsa" "key_algo_params=P-256" \
        "validity_days=${days}")
    printf '%s' "${loc#/certs/}"
}

issue_leaf() {
    # issue_leaf <parent_id> <CN> <san_dns> [validity_days]
    local parent="$1" cn="$2" sans="$3" days="${4:-90}" loc
    loc=$(submit_form /certs/new/leaf \
        "parent_id=${parent}" "subject_cn=${cn}" \
        "key_algo=ecdsa" "key_algo_params=P-256" \
        "san_dns=${sans}" \
        "validity_days=${days}")
    printf '%s' "${loc#/certs/}"
}

seed_certs() {
    log "issuing seed chain"
    local root_id inter_id legacy_root_id legacy_inter_id

    root_id=$(issue_root "LAN Root CA")
    log "  root: ${root_id} (LAN Root CA)"

    inter_id=$(issue_intermediate "${root_id}" "LAN Issuing CA G1")
    log "  intermediate: ${inter_id} (LAN Issuing CA G1)"

    # A second, older root + intermediate so the operator sees what a
    # multi-CA install looks like.
    legacy_root_id=$(issue_root "LAN Root CA (legacy)" 3650)
    log "  root: ${legacy_root_id} (LAN Root CA — legacy)"
    legacy_inter_id=$(issue_intermediate "${legacy_root_id}" "LAN Issuing CA (legacy)" 1825)
    log "  intermediate: ${legacy_inter_id} (LAN Issuing CA — legacy)"

    # Healthy leaves under the active intermediate.
    issue_leaf "${inter_id}" "git.lan"        "git.lan"                       180 >/dev/null
    log "  leaf: git.lan"
    issue_leaf "${inter_id}" "registry.lan"   "registry.lan,oci.lan"          180 >/dev/null
    log "  leaf: registry.lan / oci.lan"
    issue_leaf "${inter_id}" "ldap.lan"       "ldap.lan"                      180 >/dev/null
    log "  leaf: ldap.lan"
    issue_leaf "${inter_id}" "vault.lan"      "vault.lan,vault-ui.lan"        180 >/dev/null
    log "  leaf: vault.lan / vault-ui.lan"

    # An expiring-soon leaf so the UI status pills aren't all green.
    issue_leaf "${inter_id}" "prometheus.lan" "prometheus.lan"                25 >/dev/null
    log "  leaf: prometheus.lan (expiring in 25d)"

    # A leaf under the legacy intermediate so the issuer column shows variety.
    issue_leaf "${legacy_inter_id}" "jenkins.lan" "jenkins.lan,ci.lan"         180 >/dev/null
    log "  leaf: jenkins.lan / ci.lan (legacy chain)"
}

# ---- entry point -----------------------------------------------------------

main() {
    stop_existing_server
    wipe_data
    start_server
    setup_passphrase
    seed_certs

    cat <<EOF

  homepki dev server is running.

    URL:        ${BASE_URL}
    passphrase: ${PASSPHRASE}
    data dir:   ${DATA_DIR}
    log:        ${LOGFILE}
    pid:        $(cat "${PIDFILE}")  (kill via: kill \$(cat ${PIDFILE}))

  Re-run scripts/dev-bootstrap.sh to wipe and reseed.
EOF
}

main "$@"
