# nftables-blacklist (formerly ipset-blacklist)

[![CI](https://github.com/trick77/nftables-blacklist/actions/workflows/ci.yaml/badge.svg)](https://github.com/trick77/nftables-blacklist/actions/workflows/ci.yaml)
[![Bash 4.0+](https://img.shields.io/badge/bash-4.0%2B-blue)](https://www.gnu.org/software/bash/)
[![License](https://img.shields.io/github/license/trick77/nftables-blacklist)](LICENSE)

> 📢 Freshly defrosted from the GitHub Arctic Code Vault and upgraded from iptables to nftables. Yes, the nftables syntax is... an acquired taste. But I finally bow to the netfilter overlords.
>
> **Early stage** - expect bugs.

A Bash script that automatically downloads public IP blacklists and blocks them using nftables to keep script kiddies, botnets, and other unwanted traffic off your Linux server. Supports IPv4, IPv6, and CIDR aggregation with built-in whitelisting, cron scheduling, and automatic server IP detection.

```
Downloading blacklists..............................................
Downloaded 43 of 43 blacklists
Processing IPv4 addresses...
  CIDR optimization: 104791 → 66178 entries
Processing IPv6 addresses...
Auto-detecting server IPs for whitelist...
  Whitelisted: 2001:db8:305:2100::1
  Whitelisted: 203.0.113.10
Applying IPv4 whitelist...
  Whitelist applied: 66178 → 66178 entries
Applying IPv6 whitelist...
  Note: IPv6 whitelist uses exact matching only
  Whitelist applied: 23927 → 23927 entries
Generating nftables script...
Applying nftables rules...
Blacklist update complete
  IPv4: 66178  IPv6: 23927  Total: 90105
```

> Looking for the old ipset/iptables version? See the [archive/](archive/) folder.

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Quick Start (Debian/Ubuntu)](#quick-start-debianubuntu)
- [Persistence Across Reboots](#persistence-across-reboots)
- [Automatic Updates (Systemd Timer)](#automatic-updates-systemd-timer)
- [Check Dropped Packets](#check-dropped-packets)
- [Configuration Options](#configuration-options)
- [Customizing Blacklists](#customizing-blacklists)
- [Whitelist (Prevent Self-Blocking)](#whitelist-prevent-self-blocking)
- [Dry Run Mode](#dry-run-mode)
- [Cron Mode](#cron-mode)
- [Troubleshooting](#troubleshooting)
- [Migrating from the old ipset/iptables version](#migrating-from-the-old-ipsetiptables-version)
- [Uninstall](#uninstall)
- [Contributing](#contributing)

## Features

- Uses nftables instead of the deprecated iptables/ipset combo
- IPv4 and IPv6, including CIDR notation
- Overlapping ranges are merged automatically (e.g., two /24s become one /23)
- Atomic updates — the blacklist is swapped in one transaction
- Handles 100k+ blocked IPs without breaking a sweat
- Auto-whitelist detects your server's IPs to prevent self-blocking

## Requirements

- Debian 10+ / Ubuntu 20.04+ (or any Linux with nftables)
- nftables
- iprange - combines overlapping IP ranges and handles whitelist subtraction
- curl, grep, sed, sort, wc (usually pre-installed)

## Quick Start (Debian/Ubuntu)

1. **Install helper tools:**
   ```bash
   sudo apt install curl iprange
   ```

2. **Download the script:**
   ```bash
   sudo curl -fsSL -o /usr/local/sbin/update-blacklist.sh \
     https://raw.githubusercontent.com/trick77/nftables-blacklist/master/update-blacklist.sh
   sudo chmod +x /usr/local/sbin/update-blacklist.sh
   ```

3. **Create configuration directory and download config:**
   ```bash
   sudo mkdir -p /etc/nftables-blacklist
   if [ -f /etc/nftables-blacklist/nftables-blacklist.conf ]; then
     echo "Config already exists, skipping download"
   else
     sudo curl -fsSL -o /etc/nftables-blacklist/nftables-blacklist.conf \
          https://raw.githubusercontent.com/trick77/nftables-blacklist/master/nftables-blacklist.conf
   fi
   ```

4. **Edit configuration (optional):**
   ```bash
   sudo nano /etc/nftables-blacklist/nftables-blacklist.conf
   ```

5. **Run initial update:**
   ```bash
   sudo /usr/local/sbin/update-blacklist.sh /etc/nftables-blacklist/nftables-blacklist.conf
   ```

6. **Verify it's working:**
   ```bash
   # List the blacklist table
   sudo nft list table inet blacklist

   # Show IPv4 set contents
   sudo nft list set inet blacklist blacklist4

   # Show IPv6 set contents
   sudo nft list set inet blacklist blacklist6

   # Check drop counters
   sudo nft list chain inet blacklist input
   ```

## Persistence Across Reboots

```bash
sudo cat <<'EOF' > /etc/systemd/system/nftables-blacklist.service
[Unit]
Description=nftables IP blacklist
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/update-blacklist.sh /etc/nftables-blacklist/nftables-blacklist.conf
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
```

Enable it:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now nftables-blacklist.service
```

## Automatic Updates (Systemd Timer)

```bash
sudo cat <<'EOF' > /etc/systemd/system/nftables-blacklist-update.timer
[Unit]
Description=Update nftables IP blacklist daily

[Timer]
OnCalendar=*-*-* 23:33:00
Persistent=true
RandomizedDelaySec=14400

[Install]
WantedBy=timers.target
EOF
```

```bash
sudo cat <<'EOF' > /etc/systemd/system/nftables-blacklist-update.service
[Unit]
Description=Update nftables IP blacklist
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/update-blacklist.sh --cron /etc/nftables-blacklist/nftables-blacklist.conf
EOF
```

Enable it:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now nftables-blacklist-update.timer
```

Check timer status:

```bash
systemctl list-timers nftables-blacklist-update
```

**Tip:** Once or twice daily is enough. Updating too frequently may get you banned by blacklist providers.

## Check Dropped Packets

```bash
sudo nft list chain inet blacklist input
```

Example output:

```
chain input {
    type filter hook input priority -200; policy accept;
    ip saddr @blacklist4 counter packets 1523 bytes 91380 drop comment "IPv4 blacklist"
    ip6 saddr @blacklist6 counter packets 42 bytes 3360 drop comment "IPv6 blacklist"
}
```

## Configuration Options

Edit `nftables-blacklist.conf`. Key settings:

| Setting | Default | Description |
|---------|---------|-------------|
| `ENABLE_IPV4` | yes | Block IPv4 addresses |
| `ENABLE_IPV6` | yes | Block IPv6 addresses |
| `FORCE` | yes | Automatically create the nftables table/sets if they don't exist |
| `AUTO_WHITELIST` | no | Auto-detect and whitelist your server's own IPs (setting this to `yes` is recommended) |
| `BLOCK_FORWARD` | no | Also block blacklisted IPs in the forward chain — forwarded traffic (e.g. to containers) is NOT blocked unless set to `yes` |
| `NFT_CHAIN_PRIORITY` | -200 | When to check the blacklist (-200 = very early, before most other rules) |
| `CURL_CONNECT_TIMEOUT` | 10 | Seconds to wait for blacklist server connection |
| `CURL_MAX_TIME` | 30 | Maximum seconds per blacklist download |

## Customizing Blacklists

Edit the `BLACKLISTS` array in the config file:

```bash
BLACKLISTS=(
    # Your custom local list
    "file:///etc/nftables-blacklist/custom.list"

    # Public blacklists
    "https://www.spamhaus.org/drop/drop.lasso"
    "https://lists.blocklist.de/lists/all.txt"

    # Ban an entire country (use country code like 'cn', 'ru', etc.)
    # "https://raw.githubusercontent.com/ipverse/country-ip-blocks/master/country/ru/ipv4-aggregated.txt"
)
```


## Whitelist (Prevent Self-Blocking)

Sometimes your server's IP (or a larger prefix containing it) may appear in a public blacklist. To prevent blocking yourself:

### Manual Whitelist

Edit the `WHITELIST` array in the config file:

```bash
WHITELIST=(
    "203.0.113.10"       # Your server IP
    "203.0.113.0/24"     # Your network range
    "2001:db8::1"        # IPv6 address
)
```

For IPv4, whitelisting a range like `10.0.0.0/8` will correctly exclude all IPs in that range, even if the blacklist contains individual IPs like `10.1.2.3`.

**Note:** IPv6 whitelist only matches exact addresses (CIDR ranges not supported for IPv6 whitelist).

### Auto-Detect Server IPs

To automatically whitelist your server's own IPs (recommended):

```bash
AUTO_WHITELIST=yes
```

This detects all local interface IPs and queries external services (o11.net, icanhazip.com) for your public IPs.

## Dry Run Mode

Test without actually applying rules:

```bash
update-blacklist.sh --dry-run /etc/nftables-blacklist/nftables-blacklist.conf
```

Downloads and processes everything but doesn't actually load the rules.

## Cron Mode

Use `--cron` for automated/scheduled runs (systemd timers, cron jobs):

```bash
update-blacklist.sh --cron /etc/nftables-blacklist/nftables-blacklist.conf
```

Adds structured log prefixes (`info:`, `warn:`, `error:`) to all output and suppresses interactive formatting (progress dots, blank lines). This makes the output easier to filter with tools like logcheck or parse in journalctl and log files.

## Troubleshooting

### "nftables table does not exist"

The script creates the nftables table/sets automatically when `FORCE=yes` (the default). If you see this error, make sure `FORCE=yes` in your config.

### Check if an IP is blocked

```bash
sudo nft get element inet blacklist blacklist4 '{ 1.2.3.4 }'
sudo nft get element inet blacklist blacklist6 '{ 2001:db8::1 }'
```

### Integration with existing firewall

The script uses its own nftables table (`inet blacklist`) and won't conflict with your existing firewall. The default priority (-200) means packets hit the blacklist before most other rules. Adjust `NFT_CHAIN_PRIORITY` if needed.

### Forwarded traffic not blocked

By default, the blacklist only hooks into the `input` chain, which protects the host itself. Forwarded traffic (e.g. to Docker containers) bypasses it entirely. The script will warn you if it detects existing forward chains in nftables while `BLOCK_FORWARD` is not configured. To extend protection to forwarded traffic, set `BLOCK_FORWARD=yes` in your configuration. This adds a `forward` chain that reuses the same IP sets — no data is duplicated. Set `BLOCK_FORWARD=no` to dismiss the warning.

### Large IP sets (100k+ entries)

With very large sets you may see "Message too long" or "No buffer space available" errors. Bump the kernel network buffer:

```bash
# Add to /etc/sysctl.d/99-nftables.conf
net.core.rmem_max = 8388608
net.core.rmem_default = 8388608

# Apply now
sysctl -p /etc/sysctl.d/99-nftables.conf
```

## Migrating from the old ipset/iptables version

1. Remove the old ipset/iptables rules and clean up legacy files. The exact paths may vary depending on how you originally set it up — the commands below are examples based on the default configuration:
   ```bash
   # Remove iptables rule and ipset
   iptables -D INPUT -m set --match-set blacklist src -j DROP
   ipset destroy blacklist

   # Remove old cron job
   rm -f /etc/cron.d/update-blacklist

   # Remove old script
   rm -f /usr/local/sbin/update-blacklist.sh

   # Before deleting, check for any custom blacklists or URLs you want to preserve:
   # - Custom blacklist file: /etc/ipset-blacklist/ip-blacklist-custom.list
   # - Custom blacklist URLs in: /etc/ipset-blacklist/ipset-blacklist.conf (BLACKLISTS array)
   # Back up anything you need, then remove the old config and data directory
   rm -rI /etc/ipset-blacklist
   ```
2. Set up the new nftables version (see Quick Start)

> **Stale rule?** If the `iptables -D ... --match-set` command fails with *"Set blacklist doesn't exist"*, the ipset is already gone but a stale rule remains. Delete it by rule number instead:
> ```bash
> iptables -L INPUT --line-numbers
> iptables -D INPUT <rule-number>
> ```

> **Note for Debian Trixie (and newer) users:** On modern Debian, `iptables` is usually just a compatibility layer (`iptables-nft`) that translates commands to nftables under the hood. If you previously switched to the legacy iptables backend (`iptables-legacy` / `update-alternatives --set iptables /usr/sbin/iptables-legacy`), you'll need to switch back to the nftables backend for this script to work:
> ```bash
> update-alternatives --set iptables /usr/sbin/iptables-nft
> update-alternatives --set ip6tables /usr/sbin/ip6tables-nft
> ```

## Uninstall

To completely remove nftables-blacklist from your system:

1. **Stop and disable the systemd timer and service:**
   ```bash
   sudo systemctl disable --now nftables-blacklist-update.timer
   sudo systemctl disable --now nftables-blacklist.service
   ```

2. **Remove the nftables blacklist table** (drops all blacklist rules and sets at once):
   ```bash
   sudo nft delete table inet blacklist
   ```

3. **Remove systemd unit files:**
   ```bash
   sudo rm -f /etc/systemd/system/nftables-blacklist.service
   sudo rm -f /etc/systemd/system/nftables-blacklist-update.service
   sudo rm -f /etc/systemd/system/nftables-blacklist-update.timer
   sudo systemctl daemon-reload
   ```

4. **Remove the script:**
   ```bash
   sudo rm -f /usr/local/sbin/update-blacklist.sh
   ```

5. **Remove configuration and data:**
   ```bash
   sudo rm -rI /etc/nftables-blacklist
   ```

6. **Remove sysctl tweaks** (only if you added the buffer size workaround):
   ```bash
   sudo rm -f /etc/sysctl.d/99-nftables.conf
   sudo sysctl --system
   ```

After these steps, no traces of the blacklist remain and all previously blocked traffic will flow normally again.

## Contributing

Found a bug? Pull requests with fixes are always welcome.

This project intentionally keeps a narrow focus, so install scripts, additional OS/distro support, and feature additions won't be merged. If you have something bigger in mind, you're welcome to fork and make it your own.

