# AGENTS.md

## Read CONTRIBUTING.md first

Editing this repo or opening a PR → read `CONTRIBUTING.md` and follow it, before the first
edit. Not optional. PR opened without it gets closed.

Never claim a change works because it looks correct. Run it. Cannot run it → do not open
a PR.

## Project

Bash + nftables blacklist for large public IP feeds. Debian/Ubuntu with nftables.

`archive/` = retired ipset/iptables version. Never fix it, never port changes into it.

## Verify

```bash
bash -n update-blacklist.sh
shellcheck update-blacklist.sh                           # must stay clean
./update-blacklist.sh --dry-run nftables-blacklist.conf
```

`--dry-run` is the local gate: everything except touching nftables. Change that can only
break against real `nft` → Linux run (`docker run -it --privileged debian:bookworm`,
`apt install -y nftables curl`).

Production invocation passes the config path:
`/usr/local/sbin/update-blacklist.sh /etc/nftables-blacklist/nftables-blacklist.conf`

## Invariants

Reasons the code does not state:

- **One `nft -f` transaction.** `flush set` plus `add element`, both families. No temp sets,
  no create-swap-delete. `nft -f` is already atomic; a partial apply leaves the host
  unprotected.
- **Every change lands on v4 AND v6.** `inet` is one table on purpose. A v4-only change to
  extraction, filtering, chunking or set handling is a bug.
- **Private and reserved ranges stay filtered.** A feed slipping one in can blackhole the
  host or its gateway.
- **Chain priority default stays -200.** Configurable, but changing the default reorders
  every deployed firewall.
- **`flags interval` + `auto-merge` stay.** They make CIDR entries and overlap consolidation
  work at all.
- **Keep chunking the `add element` lists.** Feeds are big enough that one statement fails.
  Correctness, not tidiness.
- **Downloads stay best-effort per feed.** One dead URL must not abort the run.
- **Never assume `iprange` ran.** CIDR optimisation is IPv4-only and optional.
- New address format → extend extraction, add a fixture. Never special-case it in the caller.

## Config contract

`nftables-blacklist.conf` is sourced as shell, so every key is a contract with deployed
hosts. Renaming or repurposing one breaks installs silently → add a new key, and keep the
sample file's defaults in step with the script's fallbacks.

`FORCE=no` must fail loudly on a missing table, set or chain, never silently protect nothing.

## Rules

- No new external tools or interpreters (`awk`, `perl`, `python`, ...). Only what the script
  already uses.
- Plain commit messages. No `feat:` / `docs():` prefixes.
