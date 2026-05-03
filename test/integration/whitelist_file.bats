#!/usr/bin/env bats
#
# Integration tests for file:// support in WHITELIST.
#

load '../helpers/test_helper'

setup() {
  command -v iprange >/dev/null || skip "iprange not installed"

  export TEST_OUTPUT_DIR="${BATS_TMPDIR}/nftables-blacklist"
  mkdir -p "${TEST_OUTPUT_DIR}"
  chmod 777 "${TEST_OUTPUT_DIR}"

  export WL_INCLUDE="${BATS_TMPDIR}/extra-whitelist.list"
  export V4_LIST="${TEST_OUTPUT_DIR}/ip-blacklist.list.v4"
  export V6_LIST="${TEST_OUTPUT_DIR}/ip-blacklist.list.v6"

  # Synthetic blacklist with the IPs we want to test whitelisting against
  export TEST_BL="${BATS_TMPDIR}/synthetic-blacklist.txt"
  cat > "${TEST_BL}" <<'EOF'
1.2.3.4
185.213.154.66
2001:4860:4860::8888
2606:4700:4700::1111
EOF
}

teardown() {
  rm -rf "${BATS_TMPDIR}/nftables-blacklist"
  rm -f "${BATS_TMPDIR}"/test-config-*.conf "${WL_INCLUDE}" "${TEST_BL}"
}

write_config() {
  local path="$1" wl="$2"
  cat > "$path" <<EOF
BLACKLISTS=( "file://${TEST_BL}" )

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
EOF
}

@test "file:// WHITELIST: filters IPv4 from blacklist" {
  cat > "${WL_INCLUDE}" <<'EOF'
185.213.154.66
EOF
  local cfg="${BATS_TMPDIR}/test-config-1.conf"
  write_config "$cfg" '"file://'"${WL_INCLUDE}"'"'

  run "${SCRIPT_PATH}" --dry-run "$cfg"

  [ "$status" -eq 0 ]
  ! grep -q "^185\.213\.154\.66$" "$V4_LIST"
  grep -q "^1\.2\.3\.4$" "$V4_LIST"
}

@test "file:// WHITELIST: filters exact-match IPv6" {
  cat > "${WL_INCLUDE}" <<'EOF'
2606:4700:4700::1111
EOF
  local cfg="${BATS_TMPDIR}/test-config-2.conf"
  write_config "$cfg" '"file://'"${WL_INCLUDE}"'"'

  run "${SCRIPT_PATH}" --dry-run "$cfg"

  [ "$status" -eq 0 ]
  ! grep -q "2606:4700:4700::1111" "$V6_LIST"
  grep -q "2001:4860:4860::8888" "$V6_LIST"
}

@test "file:// WHITELIST: comments, blank lines, whitespace are stripped" {
  cat > "${WL_INCLUDE}" <<'EOF'
# Mullvad relays
185.213.154.66
   2606:4700:4700::1111   # whitespace + inline comment

# blank lines above too
EOF
  local cfg="${BATS_TMPDIR}/test-config-3.conf"
  write_config "$cfg" '"file://'"${WL_INCLUDE}"'"'

  run "${SCRIPT_PATH}" --dry-run "$cfg"

  [ "$status" -eq 0 ]
  ! grep -q "^185\.213\.154\.66$" "$V4_LIST"
  ! grep -q "2606:4700:4700::1111" "$V6_LIST"
}

@test "file:// WHITELIST: missing file aborts the run" {
  local cfg="${BATS_TMPDIR}/test-config-4.conf"
  write_config "$cfg" '"file:///nonexistent/path-'"$$"'.list"'

  run "${SCRIPT_PATH}" --dry-run "$cfg"

  [ "$status" -ne 0 ]
  [[ "$output" == *"WHITELIST file not readable"* ]]
}

@test "WHITELIST: rejects https:// URL with a clear error" {
  local cfg="${BATS_TMPDIR}/test-config-https.conf"
  write_config "$cfg" '"https://example.com/list.txt"'

  run "${SCRIPT_PATH}" --dry-run "$cfg"

  [ "$status" -ne 0 ]
  [[ "$output" == *"WHITELIST does not support URL scheme"* ]]
}

@test "WHITELIST: rejects http:// URL with a clear error" {
  local cfg="${BATS_TMPDIR}/test-config-http.conf"
  write_config "$cfg" '"http://example.com/list.txt"'

  run "${SCRIPT_PATH}" --dry-run "$cfg"

  [ "$status" -ne 0 ]
  [[ "$output" == *"WHITELIST does not support URL scheme"* ]]
}

@test "file:// WHITELIST: mixed literal + file entries both apply" {
  cat > "${WL_INCLUDE}" <<'EOF'
185.213.154.66
EOF
  local cfg="${BATS_TMPDIR}/test-config-5.conf"
  write_config "$cfg" '"2606:4700:4700::1111" "file://'"${WL_INCLUDE}"'"'

  run "${SCRIPT_PATH}" --dry-run "$cfg"

  [ "$status" -eq 0 ]
  # From file
  ! grep -q "^185\.213\.154\.66$" "$V4_LIST"
  # From literal
  ! grep -q "2606:4700:4700::1111" "$V6_LIST"
  # Survives
  grep -q "^1\.2\.3\.4$" "$V4_LIST"
  grep -q "2001:4860:4860::8888" "$V6_LIST"
}
