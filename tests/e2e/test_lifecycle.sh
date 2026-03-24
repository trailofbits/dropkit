#!/usr/bin/env bash
#
# E2E test: dropkit create → SSH commands → dropkit destroy
#
# Verifies the full droplet lifecycle including SSH config management.
# Designed to run in CI or locally — requires a valid dropkit config.
#
# Usage:
#   ./tests/e2e/test_lifecycle.sh
#
# Environment variables (all optional):
#   DROPLET_NAME     — Name for the test droplet (default: e2e-<timestamp>)
#   DROPLET_REGION   — Region slug (default: random from nyc3, sfo3, lon1)
#   DROPLET_SIZE     — Size slug (default: random from s-1vcpu-1gb, s-2vcpu-4gb)
#   DROPLET_IMAGE    — Image slug (default: random from ubuntu-24-04-x64, ubuntu-25-04-x64, ubuntu-25-10-x64)
#   E2E_SSH_TIMEOUT  — SSH connect timeout in seconds (default: 10)

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DROPLET_NAME="${DROPLET_NAME:-e2e-$(head -c4 /dev/urandom | od -An -tx1 | tr -d ' \n')}"
SSH_HOSTNAME="dropkit.${DROPLET_NAME}"
SSH_CONFIG="${HOME}/.ssh/config"
SSH_TIMEOUT="${E2E_SSH_TIMEOUT:-10}"
SSH_OPTS="-o StrictHostKeyChecking=accept-new -o ConnectTimeout=${SSH_TIMEOUT} -o BatchMode=yes"

# Randomized defaults — avoid hidden dependencies on specific slugs
_REGIONS=(nyc3 sfo3 lon1)
_SIZES=(s-1vcpu-1gb s-2vcpu-4gb)
_IMAGES=(ubuntu-24-04-x64 ubuntu-25-04-x64 ubuntu-25-10-x64)

_pick() {
  local -n arr=$1
  echo "${arr[RANDOM % ${#arr[@]}]}"
}

DROPLET_REGION="${DROPLET_REGION:-$(_pick _REGIONS)}"
DROPLET_SIZE="${DROPLET_SIZE:-$(_pick _SIZES)}"
DROPLET_IMAGE="${DROPLET_IMAGE:-$(_pick _IMAGES)}"

CREATE_FLAGS=(
    --no-tailscale --verbose
    --region "$DROPLET_REGION"
    --size "$DROPLET_SIZE"
    --image "$DROPLET_IMAGE"
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

TESTS_PASSED=0
TESTS_FAILED=0
DROPLET_CREATED=false

log()      { echo -e "${DIM}[$(date +%H:%M:%S)]${NC} $*"; }
log_step() { echo -e "\n${BOLD}${CYAN}=== $* ===${NC}"; }
log_ok()   { echo -e "  ${GREEN}✓${NC} $*"; }
log_fail() { echo -e "  ${RED}✗${NC} $*"; }
log_warn() { echo -e "  ${YELLOW}!${NC} $*"; }

assert() {
    local description="$1"
    shift
    if "$@" >/dev/null 2>&1; then
        log_ok "PASS: ${description}"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        log_fail "FAIL: ${description}"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
}

assert_file_contains() {
    local description="$1" file="$2" pattern="$3"
    if grep -qF "$pattern" "$file" 2>/dev/null; then
        log_ok "PASS: ${description}"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        log_fail "FAIL: ${description} — '${pattern}' not found in ${file}"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
}

assert_file_not_contains() {
    local description="$1" file="$2" pattern="$3"
    if ! grep -qF "$pattern" "$file" 2>/dev/null; then
        log_ok "PASS: ${description}"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        log_fail "FAIL: ${description} — '${pattern}' unexpectedly found in ${file}"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
}

ssh_run() {
    # shellcheck disable=SC2086,SC2029
    ssh ${SSH_OPTS} "${SSH_HOSTNAME}" "$@" 2>&1
}

# shellcheck disable=SC2329  # invoked via trap
cleanup() {
    if [[ "${DROPLET_CREATED}" == "true" ]]; then
        echo ""
        log_warn "Cleanup: destroying droplet ${DROPLET_NAME}..."
        printf 'yes\n%s\ny\n' "${DROPLET_NAME}" \
            | uv run dropkit destroy "${DROPLET_NAME}" 2>&1 || true
        DROPLET_CREATED=false
    fi
}

trap cleanup EXIT

# ---------------------------------------------------------------------------
# Pre-flight
# ---------------------------------------------------------------------------

log_step "Pre-flight checks"

log "Droplet name : ${DROPLET_NAME}"
log "SSH hostname : ${SSH_HOSTNAME}"
log "SSH config   : ${SSH_CONFIG}"
log "Create flags : ${CREATE_FLAGS[*]}"
log ""

assert "dropkit is installed" uv run dropkit version
assert "SSH config file exists" test -f "${SSH_CONFIG}"

# Ensure no leftover entry from a previous failed run
if grep -qF "Host ${SSH_HOSTNAME}" "${SSH_CONFIG}" 2>/dev/null; then
    log_warn "Stale SSH entry found for ${SSH_HOSTNAME} — aborting to avoid conflicts"
    log_warn "Remove it manually or pick a different DROPLET_NAME"
    exit 1
fi

# ---------------------------------------------------------------------------
# Step 1: Create droplet
# ---------------------------------------------------------------------------

log_step "Step 1: Create droplet"

uv run dropkit create "${DROPLET_NAME}" "${CREATE_FLAGS[@]}"
DROPLET_CREATED=true

log "Droplet created."

# ---------------------------------------------------------------------------
# Step 2: Verify SSH config after create
# ---------------------------------------------------------------------------

log_step "Step 2: Verify SSH config (post-create)"

assert_file_contains \
    "SSH config contains Host entry for droplet" \
    "${SSH_CONFIG}" "Host ${SSH_HOSTNAME}"

assert_file_contains \
    "SSH config entry has ForwardAgent yes" \
    "${SSH_CONFIG}" "ForwardAgent yes"

# Extract the IP that was written to SSH config
DROPLET_IP=$(grep -A5 "Host ${SSH_HOSTNAME}" "${SSH_CONFIG}" \
    | grep "HostName" | head -1 | awk '{print $2}')

if [[ -z "${DROPLET_IP}" ]]; then
    log_fail "Could not extract droplet IP from SSH config"
    ((TESTS_FAILED++))
else
    log "Droplet IP: ${DROPLET_IP}"
    assert "Droplet IP looks like an IPv4 address" \
        bash -c "[[ '${DROPLET_IP}' =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]"
fi

# ---------------------------------------------------------------------------
# Step 3: Run commands on the droplet via SSH
# ---------------------------------------------------------------------------

log_step "Step 3: Run commands on the droplet"

# Basic connectivity
output=$(ssh_run "echo 'hello-from-droplet'")
assert "SSH echo returns expected string" bash -c "[[ '${output}' == *hello-from-droplet* ]]"

# Kernel check
uname_output=$(ssh_run "uname -s")
assert "Remote OS is Linux" bash -c "[[ '${uname_output}' == *Linux* ]]"

# Uptime (proves the system is live and responding)
uptime_output=$(ssh_run "uptime")
log "Remote uptime: ${uptime_output}"
assert "uptime command succeeds" test -n "${uptime_output}"

# Disk space
df_output=$(ssh_run "df -h /")
log "Remote disk:"
echo "${df_output}" | while IFS= read -r line; do log "  ${line}"; done
assert "df reports a filesystem" bash -c "[[ '${df_output}' == */* ]]"

# Cloud-init final status
cloud_init_output=$(ssh_run "cloud-init status --format=json" || true)
log "Cloud-init status: ${cloud_init_output}"
assert "Cloud-init reports done" \
    bash -c "echo '${cloud_init_output}' | grep -q '\"done\"'"

# ---------------------------------------------------------------------------
# Step 4: Destroy droplet
# ---------------------------------------------------------------------------

log_step "Step 4: Destroy droplet"

# Answers: 1) "yes" to confirm  2) droplet name  3) "y" to remove known_hosts
printf 'yes\n%s\ny\n' "${DROPLET_NAME}" \
    | uv run dropkit destroy "${DROPLET_NAME}"
DROPLET_CREATED=false

log "Droplet destroyed."

# ---------------------------------------------------------------------------
# Step 5: Verify SSH config after destroy
# ---------------------------------------------------------------------------

log_step "Step 5: Verify SSH config (post-destroy)"

assert_file_not_contains \
    "SSH config no longer contains Host entry" \
    "${SSH_CONFIG}" "Host ${SSH_HOSTNAME}"

if [[ -n "${DROPLET_IP:-}" ]]; then
    assert_file_not_contains \
        "SSH config no longer references droplet IP" \
        "${SSH_CONFIG}" "HostName ${DROPLET_IP}"
fi

# Verify known_hosts was cleaned up (best-effort — entry may have been hashed)
KNOWN_HOSTS="${HOME}/.ssh/known_hosts"
if [[ -f "${KNOWN_HOSTS}" ]]; then
    assert_file_not_contains \
        "known_hosts does not contain SSH hostname" \
        "${KNOWN_HOSTS}" "${SSH_HOSTNAME}"

    if [[ -n "${DROPLET_IP:-}" ]]; then
        assert_file_not_contains \
            "known_hosts does not contain droplet IP" \
            "${KNOWN_HOSTS}" "${DROPLET_IP}"
    fi
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

log_step "Results"

TOTAL=$((TESTS_PASSED + TESTS_FAILED))
echo ""
log "Passed : ${TESTS_PASSED}/${TOTAL}"
log "Failed : ${TESTS_FAILED}/${TOTAL}"
echo ""

if [[ "${TESTS_FAILED}" -gt 0 ]]; then
    echo -e "${RED}${BOLD}SOME TESTS FAILED${NC}"
    exit 1
fi

echo -e "${GREEN}${BOLD}ALL TESTS PASSED${NC}"
exit 0
