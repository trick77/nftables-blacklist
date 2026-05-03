#!/usr/bin/env bash
#
# nftables-blacklist - Block malicious IPs using nftables sets
#
# Usage: update-blacklist.sh [OPTIONS] <configuration file>
#
# Options:
#   --dry-run  Download and process IPs, generate script, but don't apply
#   --cron     Add structured log prefixes (info:/warn:/error:) for cron jobs
#   --help     Show this help message
#
# Example:
#   update-blacklist.sh /etc/nftables-blacklist/nftables-blacklist.conf
#   update-blacklist.sh --dry-run /etc/nftables-blacklist/nftables-blacklist.conf
#

set -euo pipefail

#=============================================================================
# GLOBAL VARIABLES
#=============================================================================

DRY_RUN=no
CRON_MODE=no
CONFIG_FILE=""


# Temporary files (set in main, cleaned up on exit)
declare -a TEMP_FILES=()

#=============================================================================
# UTILITY FUNCTIONS
#=============================================================================

# Check if command exists in PATH
exists() {
  command -v "$1" >/dev/null 2>&1
}

# Print info message
log_info() {
  if [[ "$CRON_MODE" == "yes" ]]; then
    [[ -z "$*" ]] && return
    local msg="$*"
    echo "info: ${msg#"${msg%%[! ]*}"}"
  else
    echo "$*"
  fi
}

# Print error to stderr
log_error() {
  if [[ "$CRON_MODE" == "yes" ]]; then
    echo >&2 "error: $*"
  else
    echo >&2 "Error: $*"
  fi
}

# Print warning to stderr
log_warn() {
  if [[ "$CRON_MODE" == "yes" ]]; then
    echo >&2 "warn: $*"
  else
    echo >&2 "Warning: $*"
  fi
}

# Fatal error - print message and exit
die() {
  log_error "$@"
  exit 1
}

# Show progress dot (suppressed in cron mode)
show_progress() {
  [[ "$CRON_MODE" == "yes" ]] && return 0
  echo -n "."
}

# Create temp file and register for cleanup
make_temp() {
  local tmp
  tmp=$(mktemp)
  TEMP_FILES+=("$tmp")
  echo "$tmp"
}

# Cleanup temporary files
cleanup() {
  for f in "${TEMP_FILES[@]:-}"; do
    [[ -f "$f" ]] && rm -f "$f" || true
  done
  return 0
}

# Show usage information
show_help() {
  cat <<'EOF'
nftables-blacklist - Block malicious IPs using nftables sets

Usage: update-blacklist.sh [OPTIONS] <configuration file>

Options:
  --dry-run  Download and process IPs, generate nftables script,
             but don't actually apply rules. Useful for testing.
  --cron     Add structured log prefixes (info:/warn:/error:) for cron jobs.
  --help     Show this help message

Examples:
  # Normal run
  update-blacklist.sh /etc/nftables-blacklist/nftables-blacklist.conf

  # Dry run (test without applying)
  update-blacklist.sh --dry-run /etc/nftables-blacklist/nftables-blacklist.conf

Configuration:
  See nftables-blacklist.conf for all available options.

For more information: https://github.com/trick77/nftables-blacklist
EOF
}

#=============================================================================
# IP EXTRACTION FUNCTIONS
#=============================================================================

# Extract IPv4 addresses from input file
# Handles: bare IPs, CIDR notation, leading zeros normalization
# Output: one IP/CIDR per line
extract_ipv4() {
  local input_file="$1"

  # Match IPv4 addresses with optional /prefix
  # Uses grep -oE for portability (works on BSD and GNU grep)
  # Then normalize leading zeros in each octet using sed
  grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?' "$input_file" 2>/dev/null | \
  sed -E 's/^0*([0-9]+)\.0*([0-9]+)\.0*([0-9]+)\.0*([0-9]+)/\1.\2.\3.\4/' || true
}

# Extract IPv6 addresses from input file
# Handles: full form, compressed (::), CIDR notation
# Output: one IP/CIDR per line (lowercase)
extract_ipv6() {
  local input_file="$1"

  # IPv6 regex patterns - uses grep -oE for portability
  # Matches various IPv6 formats including compressed notation
  # Full: 2001:0db8:85a3:0000:0000:8a2e:0370:7334
  # Compressed: 2001:db8::1, ::1, ::, fe80::1
  # With CIDR: 2001:db8::/32

  grep -oiE '([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}(/[0-9]{1,3})?|([0-9a-fA-F]{1,4}:){1,7}:(/[0-9]{1,3})?|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}(/[0-9]{1,3})?|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}(/[0-9]{1,3})?|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}(/[0-9]{1,3})?|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}(/[0-9]{1,3})?|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}(/[0-9]{1,3})?|[0-9a-fA-F]{1,4}:(:[0-9a-fA-F]{1,4}){1,6}(/[0-9]{1,3})?|:(:[0-9a-fA-F]{1,4}){1,7}(/[0-9]{1,3})?|::(/[0-9]{1,3})?' "$input_file" 2>/dev/null | \
  tr '[:upper:]' '[:lower:]' || true
}

#=============================================================================
# IP FILTERING FUNCTIONS
#=============================================================================

# Filter out private/reserved IPv4 ranges
# Input: file with one IP/CIDR per line
# Output: filtered IPs to stdout
filter_private_ipv4() {
  local input_file="$1"

  # Remove:
  # 0.0.0.0/8     - Current network ("this" network)
  # 10.0.0.0/8    - Private (RFC 1918)
  # 100.64.0.0/10   - Carrier-grade NAT (RFC 6598)
  # 127.0.0.0/8   - Loopback
  # 169.254.0.0/16  - Link-local
  # 172.16.0.0/12   - Private (RFC 1918)
  # 192.0.0.0/24  - IETF Protocol Assignments
  # 192.0.2.0/24  - Documentation (TEST-NET-1)
  # 192.168.0.0/16  - Private (RFC 1918)
  # 198.18.0.0/15   - Benchmarking
  # 198.51.100.0/24 - Documentation (TEST-NET-2)
  # 203.0.113.0/24  - Documentation (TEST-NET-3)
  # 224.0.0.0/4   - Multicast (224-239)
  # 240.0.0.0/4   - Reserved (240-255)

  sed -r \
    -e '/^0\./d' \
    -e '/^10\./d' \
    -e '/^100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\./d' \
    -e '/^127\./d' \
    -e '/^169\.254\./d' \
    -e '/^172\.(1[6-9]|2[0-9]|3[0-1])\./d' \
    -e '/^192\.0\.0\./d' \
    -e '/^192\.0\.2\./d' \
    -e '/^192\.168\./d' \
    -e '/^198\.1[8-9]\./d' \
    -e '/^198\.51\.100\./d' \
    -e '/^203\.0\.113\./d' \
    -e '/^(22[4-9]|23[0-9]|24[0-9]|25[0-5])\./d' \
    "$input_file"
}

# Filter out private/reserved IPv6 ranges
# Input: file with one IP/CIDR per line
# Output: filtered IPs to stdout
filter_private_ipv6() {
  local input_file="$1"

  # Remove:
  # ::1       - Loopback
  # ::/128      - Unspecified
  # ::ffff:0:0/96   - IPv4-mapped
  # 64:ff9b::/96  - IPv4/IPv6 translation
  # 100::/64    - Discard prefix
  # 2001::/32     - Teredo
  # 2001:2::/48   - Benchmarking
  # 2001:db8::/32   - Documentation
  # 2001:10::/28  - ORCHID (deprecated)
  # 2002::/16     - 6to4 (deprecated)
  # fc00::/7    - Unique local (fc00::/8 and fd00::/8)
  # fe80::/10     - Link-local
  # ff00::/8    - Multicast

  grep -Eiv '^(::1(/128)?$|::(/128)?$|::ffff:|64:ff9b:|100::|2001::|2001:2:|2001:db8:|2001:10:|2002:|fc[0-9a-f]{2}:|fd[0-9a-f]{2}:|fe[89ab][0-9a-f]:|ff[0-9a-f]{2}:)' "$input_file" || true
}

#=============================================================================
# WHITELIST FUNCTIONS
#=============================================================================

# Get server IPs for auto-whitelisting
# Detects local interface IPs and optionally public IPs via external services
# Output: IPs to stdout, one per line
get_server_ips() {
  local whitelist_timeout=5

  # Get local interface IPs
  if exists ip; then
    # IPv4 from interfaces
    ip -4 addr show 2>/dev/null | grep -oE 'inet [0-9.]+' | awk '{print $2}' \
      | grep -Ev '^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|169\.254\.)' || true
    # IPv6 from interfaces
    ip -6 addr show 2>/dev/null | grep -oE 'inet6 [0-9a-fA-F:]+' | awk '{print $2}' \
      | grep -Eiv '^(::1$|::$|fe80:|f[cd][0-9a-f]{2}:)' || true
  elif exists hostname; then
    # Fallback: hostname -I (space-separated list of all IPs)
    hostname -I 2>/dev/null | tr ' ' '\n' | grep -v '^$' \
      | grep -Ev '^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|169\.254\.)' \
      | grep -Eiv '^(::1$|::$|fe80:|f[cd][0-9a-f]{2}:)' || true
  fi

  # Get public IPs via external services (with short timeout)
  # Primary: o11.net services
  # Fallback: icanhazip.com
  local public_v4="" public_v6=""

  # Try IPv4 - primary service
  public_v4=$(curl -4 -s --connect-timeout "$whitelist_timeout" --max-time "$whitelist_timeout" \
    "https://ipv4.o11.net" 2>/dev/null | grep -oE '^[0-9.]+$' || true)

  # IPv4 fallback if primary failed
  if [[ -z "$public_v4" ]]; then
    public_v4=$(curl -4 -s --connect-timeout "$whitelist_timeout" --max-time "$whitelist_timeout" \
      "https://ipv4.icanhazip.com" 2>/dev/null | grep -oE '^[0-9.]+$' || true)
  fi

  [[ -n "$public_v4" ]] && echo "$public_v4"

  # Try IPv6 - primary service
  public_v6=$(curl -6 -s --connect-timeout "$whitelist_timeout" --max-time "$whitelist_timeout" \
    "https://ipv6.o11.net" 2>/dev/null | grep -oiE '^[0-9a-f:]+$' || true)

  # IPv6 fallback if primary failed
  if [[ -z "$public_v6" ]]; then
    public_v6=$(curl -6 -s --connect-timeout "$whitelist_timeout" --max-time "$whitelist_timeout" \
      "https://ipv6.icanhazip.com" 2>/dev/null | grep -oiE '^[0-9a-f:]+$' || true)
  fi

  [[ -n "$public_v6" ]] && echo "$public_v6"
}

# Apply whitelist to filter out protected IPs from blacklist
# For IPv4: uses iprange --except for proper CIDR subtraction
# For IPv6: uses exact match filtering (no CIDR support)
# Arguments:
#   $1 - input blacklist file
#   $2 - whitelist file
#   $3 - output filtered file
#   $4 - IP version: "4" or "6"
apply_whitelist() {
  local blacklist_file="$1"
  local whitelist_file="$2"
  local output_file="$3"
  local ip_version="$4"

  if [[ "$ip_version" == "4" ]]; then
    # IPv4: use iprange for proper CIDR subtraction. Fail closed: if iprange
    # errors out we'd otherwise ship the unfiltered blacklist to nft, which
    # blacklists exactly the IPs the operator told us to protect - the same
    # failure mode the file:// missing-file die guards against.
    if ! iprange "$blacklist_file" --except "$whitelist_file" > "$output_file" 2>/dev/null; then
      die "iprange whitelist filtering failed; aborting to avoid blacklisting whitelisted IPs"
    fi
  else
    # IPv6: exact match filtering only (iprange doesn't support IPv6).
    # This means 2001:db8::1 in whitelist won't filter 2001:db8::/32 in blacklist.
    # grep exit codes: 0 = matches printed, 1 = no lines matched (legitimate
    # when every blacklist entry was whitelisted), 2+ = real error. Only the
    # last case should abort.
    set +e
    grep -v -F -x -f "$whitelist_file" "$blacklist_file" > "$output_file" 2>/dev/null
    local grep_status=$?
    set -e
    if [[ $grep_status -gt 1 ]]; then
      die "grep whitelist filtering failed (exit $grep_status); aborting to avoid blacklisting whitelisted IPs"
    fi
    log_info "  Note: IPv6 whitelist uses exact matching only"
  fi

  return 0
}

#=============================================================================
# NFTABLES MANAGEMENT FUNCTIONS
#=============================================================================

# Check if nftables table exists
check_nft_table() {
  nft list table inet "${NFT_TABLE_NAME}" >/dev/null 2>&1
}

# Create the complete nftables structure (table, sets, chain)
create_nft_structure() {
  local nft_script
  nft_script=$(make_temp)

  # Build optional forward chain block
  local forward_chain=""
  if [[ "${BLOCK_FORWARD}" == "yes" ]]; then
    forward_chain="

  chain forward {
    type filter hook forward priority ${NFT_CHAIN_PRIORITY}; policy accept;
    ip saddr @${NFT_SET_NAME_V4} counter drop comment \"IPv4 blacklist\"
    ip6 saddr @${NFT_SET_NAME_V6} counter drop comment \"IPv6 blacklist\"
  }"
  fi

  cat > "$nft_script" <<EOF
#!/usr/sbin/nft -f

# nftables-blacklist: Create table, sets, and chain
table inet ${NFT_TABLE_NAME} {
  set ${NFT_SET_NAME_V4} {
    type ipv4_addr
    flags interval
    auto-merge
  }

  set ${NFT_SET_NAME_V6} {
    type ipv6_addr
    flags interval
    auto-merge
  }

  chain ${NFT_CHAIN_NAME} {
    type filter hook input priority ${NFT_CHAIN_PRIORITY}; policy accept;
    ip saddr @${NFT_SET_NAME_V4} counter drop comment "IPv4 blacklist"
    ip6 saddr @${NFT_SET_NAME_V6} counter drop comment "IPv6 blacklist"
  }${forward_chain}
}
EOF

  log_info "Creating nftables table '${NFT_TABLE_NAME}'..."

  if [[ "$DRY_RUN" == "yes" ]]; then
    log_info "[DRY-RUN] Would execute: nft -f $nft_script"
    cat "$nft_script"
    return 0
  fi

  if nft -f "$nft_script"; then
    return 0
  else
    return 1
  fi
}

# Output chunked nft add commands for a set
# Args: $1=file, $2=set_name, $3=comment
output_chunked_elements() {
  local file="$1" set_name="$2" comment="$3"
  local chunk_size="${CHUNK_SIZE:-5000}"
  local -a chunk_array
  local joined

  [[ -s "$file" ]] || return 0

  echo ""
  echo "# $comment"

  while mapfile -t -n "$chunk_size" chunk_array && (( ${#chunk_array[@]} > 0 )); do
    printf -v joined ', %s' "${chunk_array[@]}"
    echo "add element inet ${NFT_TABLE_NAME} ${set_name} { ${joined:2} }"
  done < "$file"
}

# Generate nftables script for atomic update
generate_nft_script() {
  local ipv4_file="$1" ipv6_file="$2" output_script="$3"

  {
    echo "#!/usr/sbin/nft -f"
    echo ""
    echo "# nftables-blacklist atomic update"
    echo "# Generated: $(date -Iseconds)"
    echo ""
    echo "flush set inet ${NFT_TABLE_NAME} ${NFT_SET_NAME_V4}"
    echo "flush set inet ${NFT_TABLE_NAME} ${NFT_SET_NAME_V6}"

    output_chunked_elements "$ipv4_file" "$NFT_SET_NAME_V4" "IPv4 addresses"
    output_chunked_elements "$ipv6_file" "$NFT_SET_NAME_V6" "IPv6 addresses"
  } > "$output_script"
}

# Apply nftables script atomically
apply_nft_script() {
  local script_file="$1"

  if [[ "$DRY_RUN" == "yes" ]]; then
    log_info ""
    log_info "[DRY-RUN] Would apply: nft -f $script_file"
    return 0
  fi

  # Validate script syntax first (dry-run)
  if ! nft -c -f "$script_file" 2>/dev/null; then
    log_error "nftables script validation failed"
    log_error "Script location: $script_file"
    return 1
  fi

  # Apply atomically
  if ! nft -f "$script_file"; then
    log_error "Failed to apply nftables script"
    return 1
  fi

  return 0
}

#=============================================================================
# DOWNLOAD FUNCTIONS
#=============================================================================

# Download a single blacklist URL
# Returns: 0 on success, 1 on failure
download_blacklist() {
  local url="$1"
  local output_file="$2"
  local http_code

  http_code=$(curl -L \
    -A "nftables-blacklist/script/github" \
    --connect-timeout "${CURL_CONNECT_TIMEOUT:-10}" \
    --max-time "${CURL_MAX_TIME:-30}" \
    -o "$output_file" \
    -s \
    -w "%{http_code}" \
    "$url" 2>/dev/null) || true

  case "$http_code" in
    200|301|302|000)
      # 200 = OK
      # 301/302 = Redirect (already followed by -L)
      # 000 = file:// URL
      return 0
      ;;
    503)
      log_warn "Service unavailable (503): $url"
      return 1
      ;;
    *)
      log_warn "HTTP $http_code: $url"
      return 1
      ;;
  esac
}

# Download all blacklists and extract IPs
download_all_blacklists() {
  local ipv4_output="$1"
  local ipv6_output="$2"
  local success_count=0
  local total_count=${#BLACKLISTS[@]}

  for url in "${BLACKLISTS[@]}"; do
    # Skip commented entries (shouldn't happen after sourcing, but be safe)
    [[ "$url" =~ ^# ]] && continue

    local dl_tmp
    dl_tmp=$(make_temp)

    if download_blacklist "$url" "$dl_tmp"; then
      # Extract IPv4 if enabled
      if [[ "${ENABLE_IPV4:-yes}" == "yes" ]]; then
        extract_ipv4 "$dl_tmp" >> "$ipv4_output"
      fi

      # Extract IPv6 if enabled
      if [[ "${ENABLE_IPV6:-yes}" == "yes" ]]; then
        extract_ipv6 "$dl_tmp" >> "$ipv6_output"
      fi

      ((success_count++)) || true
      show_progress
    fi
  done

  log_info ""

  if (( success_count == 0 )); then
    die "All blacklist downloads failed ($total_count URLs)"
  fi

  log_info "Downloaded $success_count of $total_count blacklists"
}

#=============================================================================
# MAIN FUNCTION
#=============================================================================

main() {
  # Parse command line arguments
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --dry-run)
        DRY_RUN=yes
        shift
        ;;
      --cron)
        CRON_MODE=yes
        shift
        ;;
      --help|-h)
        show_help
        exit 0
        ;;
      -*)
        die "Unknown option: $1 (use --help for usage)"
        ;;
      *)
        if [[ -z "$CONFIG_FILE" ]]; then
          CONFIG_FILE="$1"
        else
          die "Unexpected argument: $1"
        fi
        shift
        ;;
    esac
  done

  # Require config file
  if [[ -z "$CONFIG_FILE" ]]; then
    die "Please specify a configuration file, e.g. $0 /etc/nftables-blacklist/nftables-blacklist.conf"
  fi

  # Set up cleanup trap
  trap cleanup EXIT

  # Source configuration
  # shellcheck source=nftables-blacklist.conf
  if ! source "$CONFIG_FILE"; then
    die "Cannot load configuration file: $CONFIG_FILE"
  fi

  # Warn if forward chains exist but BLOCK_FORWARD not explicitly configured.
  # Only triggers when BLOCK_FORWARD is unset/empty — NOT when explicitly set to "no".
  if [[ -z "${BLOCK_FORWARD:-}" ]]; then
    if nft list chains 2>/dev/null | grep -q 'hook forward'; then
      log_warn "Forward chain(s) detected but BLOCK_FORWARD is not set in configuration."
      log_warn "Forwarded traffic (e.g. to containers) is NOT protected by the blacklist. Set BLOCK_FORWARD=yes to enable, or BLOCK_FORWARD=no to dismiss this warning."
    fi
  fi

  # Apply defaults for optional settings
  : "${NFT_TABLE_NAME:=blacklist}"
  : "${NFT_SET_NAME_V4:=blacklist4}"
  : "${NFT_SET_NAME_V6:=blacklist6}"
  : "${NFT_CHAIN_NAME:=input}"
  : "${NFT_CHAIN_PRIORITY:=-200}"
  : "${ENABLE_IPV4:=yes}"
  : "${ENABLE_IPV6:=yes}"
  : "${BLOCK_FORWARD:=no}"
  : "${CHUNK_SIZE:=5000}"
  : "${CURL_CONNECT_TIMEOUT:=10}"
  : "${CURL_MAX_TIME:=30}"

  # Validate required commands
  local required_cmds=(curl grep sed sort wc iprange)
  for cmd in "${required_cmds[@]}"; do
    if ! exists "$cmd"; then
      die "Required command not found: $cmd (install with: apt install $cmd)"
    fi
  done

  # Check for nft (unless dry-run)
  if [[ "$DRY_RUN" != "yes" ]]; then
    if ! exists nft; then
      die "nft command not found. Install nftables: apt install nftables"
    fi
    # Verify nftables version (need 0.9.0+ for interval sets with auto-merge)
    local nft_version
    nft_version=$(nft --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+' | head -1)
    if [[ -n "$nft_version" ]]; then
      local major minor
      major=${nft_version%%.*}
      minor=${nft_version#*.}
      minor=${minor%%.*}
      if (( major == 0 && minor < 9 )); then
        log_warn "nftables version $nft_version detected. Version 0.9.0+ recommended for full feature support."
      fi
    fi
  fi

  # Validate output directories exist
  local script_dir list_dir
  script_dir=$(dirname "${NFT_BLACKLIST_SCRIPT:-/etc/nftables-blacklist/blacklist.nft}")
  list_dir=$(dirname "${IP_BLACKLIST:-/etc/nftables-blacklist/ip-blacklist.list}")

  if [[ ! -d "$script_dir" ]]; then
    die "Directory does not exist: $script_dir (create it or update NFT_BLACKLIST_SCRIPT in config)"
  fi

  if [[ ! -d "$list_dir" ]]; then
    die "Directory does not exist: $list_dir (create it or update IP_BLACKLIST in config)"
  fi

  # Check/create nftables structure
  if [[ "$DRY_RUN" != "yes" ]]; then
    if ! check_nft_table; then
      if [[ "${FORCE:-no}" != "yes" ]]; then
        log_error "nftables table '${NFT_TABLE_NAME}' does not exist."
        log_error "Create it manually or set FORCE=yes in configuration."
        log_error ""
        log_error "Manual creation:"
        log_error "  nft add table inet ${NFT_TABLE_NAME}"
        log_error "  nft add set inet ${NFT_TABLE_NAME} ${NFT_SET_NAME_V4} '{ type ipv4_addr; flags interval; auto-merge; }'"
        log_error "  nft add set inet ${NFT_TABLE_NAME} ${NFT_SET_NAME_V6} '{ type ipv6_addr; flags interval; auto-merge; }'"
        log_error "  nft add chain inet ${NFT_TABLE_NAME} ${NFT_CHAIN_NAME} '{ type filter hook input priority ${NFT_CHAIN_PRIORITY}; policy accept; }'"
        log_error "  nft add rule inet ${NFT_TABLE_NAME} ${NFT_CHAIN_NAME} ip saddr @${NFT_SET_NAME_V4} counter drop"
        log_error "  nft add rule inet ${NFT_TABLE_NAME} ${NFT_CHAIN_NAME} ip6 saddr @${NFT_SET_NAME_V6} counter drop"
        if [[ "${BLOCK_FORWARD}" == "yes" ]]; then
          log_error "  nft add chain inet ${NFT_TABLE_NAME} forward '{ type filter hook forward priority ${NFT_CHAIN_PRIORITY}; policy accept; }'"
          log_error "  nft add rule inet ${NFT_TABLE_NAME} forward ip saddr @${NFT_SET_NAME_V4} counter drop"
          log_error "  nft add rule inet ${NFT_TABLE_NAME} forward ip6 saddr @${NFT_SET_NAME_V6} counter drop"
        fi
        exit 1
      fi

      if ! create_nft_structure; then
        die "Failed to create nftables structure"
      fi
    fi

    # Ensure forward chain exists when BLOCK_FORWARD is enabled on an existing table
    if [[ "${BLOCK_FORWARD}" == "yes" ]]; then
      if ! nft list chain inet "${NFT_TABLE_NAME}" forward >/dev/null 2>&1; then
        log_info "Adding forward chain to existing table '${NFT_TABLE_NAME}'..."
        nft add chain inet "${NFT_TABLE_NAME}" forward '{ type filter hook forward priority '"${NFT_CHAIN_PRIORITY}"'; policy accept; }'
        nft add rule inet "${NFT_TABLE_NAME}" forward ip saddr @"${NFT_SET_NAME_V4}" counter drop comment \"IPv4 blacklist\"
        nft add rule inet "${NFT_TABLE_NAME}" forward ip6 saddr @"${NFT_SET_NAME_V6}" counter drop comment \"IPv6 blacklist\"
      fi
    fi
  else
    log_info "[DRY-RUN] Skipping nftables table check"
  fi

  # Create temporary files for IP collection
  local ipv4_raw ipv6_raw ipv4_clean ipv6_clean
  ipv4_raw=$(make_temp)
  ipv6_raw=$(make_temp)
  ipv4_clean=$(make_temp)
  ipv6_clean=$(make_temp)

  if [[ "$CRON_MODE" == "yes" ]]; then
    log_info "Downloading blacklists..."
  else
    echo -n "Downloading blacklists..."
  fi

  # Download and extract all IPs
  download_all_blacklists "$ipv4_raw" "$ipv6_raw"

  # Process IPv4
  if [[ "${ENABLE_IPV4:-yes}" == "yes" ]]; then
    log_info "Processing IPv4 addresses..."

    if [[ -s "$ipv4_raw" ]]; then
      # Filter private ranges and deduplicate
      filter_private_ipv4 "$ipv4_raw" | sort -u > "$ipv4_clean"

      # CIDR optimization (aggregates overlapping ranges)
      if [[ -s "$ipv4_clean" ]]; then
        local before_count after_count
        before_count=$(wc -l < "$ipv4_clean")

        local ipv4_optimized
        ipv4_optimized=$(make_temp)

        if iprange --optimize "$ipv4_clean" > "$ipv4_optimized" 2>/dev/null && [[ -s "$ipv4_optimized" ]]; then
          mv "$ipv4_optimized" "$ipv4_clean"
          after_count=$(wc -l < "$ipv4_clean")
          log_info "  CIDR optimization: $before_count → $after_count entries"
        fi
      fi
    fi
  fi

  # Process IPv6
  if [[ "${ENABLE_IPV6:-yes}" == "yes" ]]; then
    log_info "Processing IPv6 addresses..."

    if [[ -s "$ipv6_raw" ]]; then
      # Filter private ranges and deduplicate
      filter_private_ipv6 "$ipv6_raw" | sort -u > "$ipv6_clean"
    fi
  fi

  # Apply whitelist filtering (if configured)
  local whitelist_v4 whitelist_v6
  whitelist_v4=$(make_temp)
  whitelist_v6=$(make_temp)
  local has_whitelist=no

  # Collect manual whitelist entries.
  # Each entry is either a literal IP/CIDR or a "file://" URL pointing at a
  # flat list (one IP/CIDR per line, '#' starts a comment). Files let users
  # plug in externally-generated whitelists (e.g. a cron-driven jq pipeline
  # against Mullvad/cloud-provider APIs) without coupling that tooling to
  # this script.
  if [[ -n "${WHITELIST[*]:-}" ]]; then
    for entry in "${WHITELIST[@]}"; do
      [[ -z "$entry" ]] && continue
      if [[ "$entry" == file://* ]]; then
        local wl_path="${entry#file://}"
        if [[ ! -r "$wl_path" ]]; then
          die "WHITELIST file not readable: $wl_path"
        fi
        local line
        while IFS= read -r line || [[ -n "$line" ]]; do
          line="${line%%#*}"
          line="${line//[[:space:]]/}"
          [[ -z "$line" ]] && continue
          if [[ "$line" == *:* ]]; then
            echo "$line" >> "$whitelist_v6"
          else
            echo "$line" >> "$whitelist_v4"
          fi
        done < "$wl_path"
      elif [[ "$entry" =~ ^[a-zA-Z][a-zA-Z0-9+.-]*:// ]]; then
        # Reject unknown URL schemes (https://, http://, ftp://, ...). The
        # WHITELIST array only accepts literal IP/CIDR entries and file://
        # paths. Silently writing an HTTPS URL into the whitelist would be
        # ignored by iprange and let the IPs the operator wanted to protect
        # get blacklisted - the same failure mode the file:// die guards.
        die "WHITELIST does not support URL scheme in entry: $entry (only literal IP/CIDR or file:// is supported; fetch external lists out-of-band)"
      elif [[ "$entry" == *:* ]]; then
        echo "$entry" >> "$whitelist_v6"
      else
        echo "$entry" >> "$whitelist_v4"
      fi
    done
    has_whitelist=yes
  fi

  # Auto-detect server IPs if enabled
  if [[ "${AUTO_WHITELIST:-no}" == "yes" ]]; then
    log_info "Auto-detecting server IPs for whitelist..."
    local auto_ips
    auto_ips=$(make_temp)
    get_server_ips | sort -u > "$auto_ips"

    if [[ -s "$auto_ips" ]]; then
      while IFS= read -r ip || [[ -n "$ip" ]]; do
        [[ -z "$ip" ]] && continue
        if [[ "$ip" == *:* ]]; then
          echo "$ip" >> "$whitelist_v6"
        else
          echo "$ip" >> "$whitelist_v4"
        fi
        log_info "  Whitelisted: $ip"
      done < "$auto_ips"
      has_whitelist=yes
    fi
  fi

  # Apply whitelist if we have entries
  if [[ "$has_whitelist" == "yes" ]]; then
    local before_wl after_wl
    # Apply IPv4 whitelist
    if [[ -s "$ipv4_clean" ]] && [[ -s "$whitelist_v4" ]]; then
      log_info "Applying IPv4 whitelist..."
      local ipv4_filtered
      ipv4_filtered=$(make_temp)
      before_wl=$(wc -l < "$ipv4_clean")

      if apply_whitelist "$ipv4_clean" "$whitelist_v4" "$ipv4_filtered" "4"; then
        mv "$ipv4_filtered" "$ipv4_clean"
        after_wl=$(wc -l < "$ipv4_clean")
        log_info "  Whitelist applied: $before_wl → $after_wl entries"
      fi
    fi

    # Apply IPv6 whitelist
    if [[ -s "$ipv6_clean" ]] && [[ -s "$whitelist_v6" ]]; then
      log_info "Applying IPv6 whitelist..."
      local ipv6_filtered
      ipv6_filtered=$(make_temp)
      before_wl=$(wc -l < "$ipv6_clean")

      if apply_whitelist "$ipv6_clean" "$whitelist_v6" "$ipv6_filtered" "6"; then
        mv "$ipv6_filtered" "$ipv6_clean"
        after_wl=$(wc -l < "$ipv6_clean")
        log_info "  Whitelist applied: $before_wl → $after_wl entries"
      fi
    fi
  fi

  # Save plain text lists for reference
  if [[ "${ENABLE_IPV4:-yes}" == "yes" ]] && [[ -s "$ipv4_clean" ]]; then
    cp "$ipv4_clean" "${IP_BLACKLIST}.v4"
  fi

  if [[ "${ENABLE_IPV6:-yes}" == "yes" ]] && [[ -s "$ipv6_clean" ]]; then
    cp "$ipv6_clean" "${IP_BLACKLIST}.v6"
  fi

  # Create combined list for backward compatibility
  cat "$ipv4_clean" "$ipv6_clean" 2>/dev/null > "$IP_BLACKLIST" || true

  log_info "Generating nftables script..."

  # Generate atomic update script
  generate_nft_script "$ipv4_clean" "$ipv6_clean" "$NFT_BLACKLIST_SCRIPT"

  log_info "Applying nftables rules..."

  # Apply atomically
  if ! apply_nft_script "$NFT_BLACKLIST_SCRIPT"; then
    die "Failed to apply blacklist"
  fi

  # Report statistics
  local v4_count v6_count
  v4_count=$(wc -l < "$ipv4_clean" 2>/dev/null || echo 0)
  v6_count=$(wc -l < "$ipv6_clean" 2>/dev/null || echo 0)

  if [[ "$CRON_MODE" == "yes" ]]; then
    log_info "Blacklist update complete"
    log_info "IPv4: $v4_count  IPv6: $v6_count  Total: $((v4_count + v6_count))"

    if [[ "$DRY_RUN" == "yes" ]]; then
      log_info "[DRY-RUN] No changes were applied to nftables"
    fi
  else
    log_info "Blacklist update complete"
    echo "  IPv4: $v4_count  IPv6: $v6_count  Total: $((v4_count + v6_count))"

    if [[ "$DRY_RUN" == "yes" ]]; then
      echo ""
      log_info "[DRY-RUN] No changes were applied to nftables"
    fi
  fi

  return 0
}

# Entry point
main "$@" || exit 1
