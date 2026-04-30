#!/usr/bin/env bats
#
# Integration matrix for whitelist modes:
#   - WHITELIST literals: empty | populated
#   - WHITELIST_JSON_SOURCES:     empty | populated
#   - jq:                 installed | not installed
#
# Each row runs in --dry-run mode and asserts whitelisted IPs are filtered
# out of the produced lists, while non-whitelisted IPs survive.
#

load '../helpers/test_helper'

setup() {
  command -v iprange >/dev/null || skip "iprange not installed"

  export TEST_OUTPUT_DIR="${BATS_TMPDIR}/nftables-blacklist"
  mkdir -p "${TEST_OUTPUT_DIR}"
  chmod 777 "${TEST_OUTPUT_DIR}"

  export TEST_BLACKLIST="file://${FIXTURES_DIR}/whitelist-test-blacklist.txt"
  export MULLVAD_URL="file://${FIXTURES_DIR}/whitelist-mullvad.json"

  export V4_LIST="${TEST_OUTPUT_DIR}/ip-blacklist.list.v4"
  export V6_LIST="${TEST_OUTPUT_DIR}/ip-blacklist.list.v6"
}

teardown() {
  rm -rf "${BATS_TMPDIR}/nftables-blacklist"
  rm -f "${BATS_TMPDIR}"/test-config-*.conf
  rm -rf "${BATS_TMPDIR}/no-jq-bin"
}

# Build a hermetic PATH containing every binary the script needs EXCEPT jq.
# Returns the path to the sandbox bin dir on stdout.
build_path_without_jq() {
  local sandbox="${BATS_TMPDIR}/no-jq-bin"
  rm -rf "$sandbox"
  mkdir -p "$sandbox"
  local cmd p
  for cmd in bash sh curl grep sed sort wc iprange awk tr cut cat dirname basename mktemp rm cp mv chmod chown date head tail tee uname env hostname ip nft true false test ls stat readlink find xargs; do
    p=$(command -v "$cmd" 2>/dev/null) || continue
    ln -sf "$p" "$sandbox/$cmd"
  done
  echo "$sandbox"
}

# Write a config file. Args: path, WHITELIST_array_literal, WHITELIST_JSON_SOURCES_array_literal
write_config() {
  local path="$1" wl="$2" wlj="$3"
  cat > "$path" <<EOF
BLACKLISTS=(
  "${TEST_BLACKLIST}"
)

NFT_BLACKLIST_SCRIPT="${TEST_OUTPUT_DIR}/blacklist.nft"
IP_BLACKLIST="${TEST_OUTPUT_DIR}/ip-blacklist.list"

NFT_TABLE_NAME="test_blacklist"
NFT_SET_NAME_V4="test_blacklist4"
NFT_SET_NAME_V6="test_blacklist6"
NFT_CHAIN_NAME="test_input"
NFT_CHAIN_PRIORITY=-200

ENABLE_IPV4=yes
ENABLE_IPV6=yes
AUTO_WHITELIST=no
CHUNK_SIZE=100

WHITELIST=( ${wl} )
WHITELIST_JSON_SOURCES=( ${wlj} )
EOF
}

#=============================================================================
# Row 1: WHITELIST empty, WHITELIST_JSON_SOURCES empty, jq installed
#=============================================================================
@test "matrix-1: no whitelists, jq present -> all blacklist IPs survive" {
  command -v jq >/dev/null || skip "jq not installed"
  local cfg="${BATS_TMPDIR}/test-config-1.conf"
  write_config "$cfg" "" ""

  run "${SCRIPT_PATH}" --dry-run "$cfg"

  [ "$status" -eq 0 ]
  grep -q "^1\.2\.3\.4$" "$V4_LIST"
  grep -q "^185\.213\.154\.66$" "$V4_LIST"
  grep -q "2001:4860:4860::8888" "$V6_LIST"
}

#=============================================================================
# Row 2: WHITELIST empty, WHITELIST_JSON_SOURCES empty, jq NOT installed
#=============================================================================
@test "matrix-2: no whitelists, jq absent -> runs, no jq required" {
  local cfg="${BATS_TMPDIR}/test-config-2.conf"
  write_config "$cfg" "" ""

  local sandbox
  sandbox=$(build_path_without_jq)

  PATH="$sandbox" run "${SCRIPT_PATH}" --dry-run "$cfg"

  [ "$status" -eq 0 ]
  grep -q "^1\.2\.3\.4$" "$V4_LIST"
}

#=============================================================================
# Row 3: WHITELIST populated, WHITELIST_JSON_SOURCES empty, jq installed
#=============================================================================
@test "matrix-3: literal whitelist only, jq present -> literal entries filtered" {
  command -v jq >/dev/null || skip "jq not installed"
  local cfg="${BATS_TMPDIR}/test-config-3.conf"
  write_config "$cfg" '"203.0.113.99" "2001:db8:dead::1"' ""

  run "${SCRIPT_PATH}" --dry-run "$cfg"

  [ "$status" -eq 0 ]
  ! grep -q "^203\.0\.113\.99$" "$V4_LIST"
  ! grep -q "^2001:db8:dead::1$" "$V6_LIST"
  # Non-whitelisted IPs must remain
  grep -q "^1\.2\.3\.4$" "$V4_LIST"
  grep -q "^185\.213\.154\.66$" "$V4_LIST"
}

#=============================================================================
# Row 4: WHITELIST populated, WHITELIST_JSON_SOURCES empty, jq NOT installed
#=============================================================================
@test "matrix-4: literal whitelist only, jq absent -> literal whitelist still works" {
  local cfg="${BATS_TMPDIR}/test-config-4.conf"
  write_config "$cfg" '"203.0.113.99" "2001:db8:dead::1"' ""

  local sandbox
  sandbox=$(build_path_without_jq)

  PATH="$sandbox" run "${SCRIPT_PATH}" --dry-run "$cfg"

  [ "$status" -eq 0 ]
  ! grep -q "^203\.0\.113\.99$" "$V4_LIST"
  ! grep -q "^2001:db8:dead::1$" "$V6_LIST"
  grep -q "^1\.2\.3\.4$" "$V4_LIST"
}

#=============================================================================
# Row 5: WHITELIST empty, WHITELIST_JSON_SOURCES populated, jq installed
#=============================================================================
@test "matrix-5: JSON whitelist only, jq present -> JSON entries filtered" {
  command -v jq >/dev/null || skip "jq not installed"
  local cfg="${BATS_TMPDIR}/test-config-5.conf"
  write_config "$cfg" "" '"'"${MULLVAD_URL}"'|.wireguard.relays[].ipv4_addr_in"'

  run "${SCRIPT_PATH}" --dry-run "$cfg"

  [ "$status" -eq 0 ]
  ! grep -q "^185\.213\.154\.66$" "$V4_LIST"
  grep -q "^1\.2\.3\.4$" "$V4_LIST"
}

#=============================================================================
# Row 6: WHITELIST empty, WHITELIST_JSON_SOURCES populated, jq NOT installed
#=============================================================================
@test "matrix-6: JSON whitelist set but jq absent -> dies before download" {
  local cfg="${BATS_TMPDIR}/test-config-6.conf"
  write_config "$cfg" "" '"'"${MULLVAD_URL}"'|.wireguard.relays[].ipv4_addr_in"'

  local sandbox
  sandbox=$(build_path_without_jq)

  PATH="$sandbox" run "${SCRIPT_PATH}" --dry-run "$cfg"

  [ "$status" -ne 0 ]
  [[ "$output" == *"Required command not found: jq"* ]]
  # No output files should have been written
  [ ! -f "$V4_LIST" ]
  [ ! -f "$V6_LIST" ]
}

#=============================================================================
# Row 7: WHITELIST populated, WHITELIST_JSON_SOURCES populated, jq installed
#=============================================================================
@test "matrix-7: both whitelists, jq present -> both sets of IPs filtered" {
  command -v jq >/dev/null || skip "jq not installed"
  local cfg="${BATS_TMPDIR}/test-config-7.conf"
  write_config "$cfg" \
    '"203.0.113.99" "2001:db8:dead::1"' \
    '"'"${MULLVAD_URL}"'|.wireguard.relays[].ipv4_addr_in"'

  run "${SCRIPT_PATH}" --dry-run "$cfg"

  [ "$status" -eq 0 ]
  # Literal whitelist
  ! grep -q "^203\.0\.113\.99$" "$V4_LIST"
  ! grep -q "^2001:db8:dead::1$" "$V6_LIST"
  # JSON whitelist
  ! grep -q "^185\.213\.154\.66$" "$V4_LIST"
  # Non-whitelisted survives
  grep -q "^1\.2\.3\.4$" "$V4_LIST"
  grep -q "2001:4860:4860::8888" "$V6_LIST"
}

#=============================================================================
# Row 8: WHITELIST populated, WHITELIST_JSON_SOURCES populated, jq NOT installed
#=============================================================================
@test "matrix-8: both whitelists set but jq absent -> dies, ignores literals too" {
  local cfg="${BATS_TMPDIR}/test-config-8.conf"
  write_config "$cfg" \
    '"203.0.113.99"' \
    '"'"${MULLVAD_URL}"'|.wireguard.relays[].ipv4_addr_in"'

  local sandbox
  sandbox=$(build_path_without_jq)

  PATH="$sandbox" run "${SCRIPT_PATH}" --dry-run "$cfg"

  [ "$status" -ne 0 ]
  [[ "$output" == *"Required command not found: jq"* ]]
}
