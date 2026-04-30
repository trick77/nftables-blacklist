#!/usr/bin/env bats
#
# Unit tests for fetch_json_whitelist() function
#

load '../helpers/test_helper'

setup() {
  command -v jq >/dev/null || skip "jq not installed"
  load_script_functions
  mkdir -p "${BATS_TMPDIR}/work"

  # Stub out logging to avoid bleeding into output
  CRON_MODE=no
  export V4_OUT="${BATS_TMPDIR}/work/v4.txt"
  export V6_OUT="${BATS_TMPDIR}/work/v6.txt"
  : > "$V4_OUT"
  : > "$V6_OUT"
}

teardown() {
  rm -rf "${BATS_TMPDIR}/work"
}

@test "fetch_json_whitelist: extracts Mullvad IPv4 relay addresses" {
  WHITELIST_JSON_SOURCES=("file://${FIXTURES_DIR}/whitelist-mullvad.json|.wireguard.relays[].ipv4_addr_in")

  run fetch_json_whitelist "$V4_OUT" "$V6_OUT"

  [ "$status" -eq 0 ]
  assert_file_contains_lines "$V4_OUT" "185.213.154.66" "185.213.154.67" "193.32.127.66"
  [ ! -s "$V6_OUT" ]
}

@test "fetch_json_whitelist: routes IPv6 to v6 output" {
  WHITELIST_JSON_SOURCES=("file://${FIXTURES_DIR}/whitelist-mullvad.json|.wireguard.relays[].ipv6_addr_in")

  run fetch_json_whitelist "$V4_OUT" "$V6_OUT"

  [ "$status" -eq 0 ]
  [ ! -s "$V4_OUT" ]
  assert_file_contains_lines "$V6_OUT" "2a03:1b20:1:f011::a01f" "2a03:1b20:1:f011::a020"
}

@test "fetch_json_whitelist: gcloud filter returns CIDRs into v4 output" {
  WHITELIST_JSON_SOURCES=("file://${FIXTURES_DIR}/whitelist-gcloud.json|.prefixes[].ipv4Prefix // empty")

  run fetch_json_whitelist "$V4_OUT" "$V6_OUT"

  [ "$status" -eq 0 ]
  assert_file_contains_lines "$V4_OUT" "34.0.0.0/15" "35.190.0.0/17"
  [ ! -s "$V6_OUT" ]
}

@test "fetch_json_whitelist: gcloud IPv6 filter routes CIDRs to v6 output" {
  WHITELIST_JSON_SOURCES=("file://${FIXTURES_DIR}/whitelist-gcloud.json|.prefixes[].ipv6Prefix // empty")

  run fetch_json_whitelist "$V4_OUT" "$V6_OUT"

  [ "$status" -eq 0 ]
  [ ! -s "$V4_OUT" ]
  assert_file_contains_lines "$V6_OUT" "2600:1900::/32" "2607:f8b0::/32"
}

@test "fetch_json_whitelist: malformed jq filter dies (fail-fast)" {
  WHITELIST_JSON_SOURCES=(
    "file://${FIXTURES_DIR}/whitelist-mullvad.json|.this is not valid jq[("
  )

  run fetch_json_whitelist "$V4_OUT" "$V6_OUT"

  [ "$status" -ne 0 ]
  [[ "$output" == *"jq filter failed"* ]]
}

@test "fetch_json_whitelist: invalid entry without pipe dies" {
  WHITELIST_JSON_SOURCES=("file://${FIXTURES_DIR}/whitelist-mullvad.json")

  run fetch_json_whitelist "$V4_OUT" "$V6_OUT"

  [ "$status" -ne 0 ]
  [[ "$output" == *"Invalid WHITELIST_JSON_SOURCES entry"* ]]
}

@test "fetch_json_whitelist: download failure dies (fail-fast)" {
  WHITELIST_JSON_SOURCES=("file://${BATS_TMPDIR}/does-not-exist-$$.json|.[]")

  run fetch_json_whitelist "$V4_OUT" "$V6_OUT"

  [ "$status" -ne 0 ]
  [[ "$output" == *"Failed to download whitelist source"* ]]
}

@test "fetch_json_whitelist: filter containing additional pipes is preserved (split on first |)" {
  # jq alternation operator '|' inside the filter should survive entry split.
  # Filter pipes the array stream through select() then extracts the field.
  WHITELIST_JSON_SOURCES=("file://${FIXTURES_DIR}/whitelist-mullvad.json|.wireguard.relays[] | select(.hostname == \"test-wg-002\") | .ipv4_addr_in")

  run fetch_json_whitelist "$V4_OUT" "$V6_OUT"

  [ "$status" -eq 0 ]
  assert_file_contains_lines "$V4_OUT" "185.213.154.67"
  assert_file_excludes_lines "$V4_OUT" "185.213.154.66" "193.32.127.66"
}

@test "fetch_json_whitelist: empty WHITELIST_JSON_SOURCES returns 1 (nothing added)" {
  WHITELIST_JSON_SOURCES=()

  run fetch_json_whitelist "$V4_OUT" "$V6_OUT"

  [ "$status" -eq 1 ]
  [ ! -s "$V4_OUT" ]
  [ ! -s "$V6_OUT" ]
}

@test "fetch_json_whitelist: filter producing empty output returns 1" {
  WHITELIST_JSON_SOURCES=("file://${FIXTURES_DIR}/whitelist-mullvad.json|.wireguard.relays[] | select(.hostname == \"does-not-exist\") | .ipv4_addr_in")

  run fetch_json_whitelist "$V4_OUT" "$V6_OUT"

  [ "$status" -eq 1 ]
  [ ! -s "$V4_OUT" ]
  [ ! -s "$V6_OUT" ]
}
