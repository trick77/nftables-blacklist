# Contributing

Found a bug? Pull requests with fixes are always welcome. A few rules keep the review
load sane.

## No unreviewed AI output

The volume of machine-generated pull requests that nobody read or ran before opening them
has gone up sharply, and reviewing them costs more time than writing the change would have.
Hence this section.

Using an AI assistant to write a patch is fine. Submitting its output without reading and
running it is not. Every pull request must have been reviewed line by line by a human who
understands what it does and has run the result. PRs that show they were never executed -
references to variables the change removed, code paths that abort on the first run - are
closed without further review.

## Run the checks before you submit

CI does not start on a first-time contributor's pull request until a maintainer approves
the run, so do not use it to find out whether your change works. Everything CI does runs
locally, and green here means green there:

```bash
shellcheck update-blacklist.sh              # severity warning, must be clean
bash -n update-blacklist.sh
grep -n '[[:blank:]]$' update-blacklist.sh  # trailing whitespace, must print nothing
bats test/unit/*.bats
bats test/integration/*.bats

sudo mkdir -p /etc/nftables-blacklist && sudo chmod 777 /etc/nftables-blacklist
./update-blacklist.sh --dry-run test/nftables-blacklist.conf
```

The last one downloads a live feed and does everything except touch nftables. It is the
gate that catches a change which is syntactically fine but dies on the first run.

Debian/Ubuntu prerequisites:

```bash
sudo apt install shellcheck iprange
git clone --depth 1 https://github.com/bats-core/bats-core.git
sudo bats-core/install.sh /usr/local
```

The pull request template asks you to paste the dry-run output. Paste the real output, not
a description of it.

## Formatting

The repo has an `.editorconfig`. Enable EditorConfig support in your editor, or match it by
hand: two-space indent, LF, UTF-8, no trailing whitespace, newline at end of file. Nothing
in CI checks this, so it is on you.

## CI must be green

A pull request whose CI is red and is not fixed will be closed. A pending check is not on
you, a failing one is.

## Scope

This project intentionally keeps a narrow focus, so install scripts, additional
OS/distro support, and feature additions won't be merged. If you have something
bigger in mind, you're welcome to fork and make it your own.

- One change per pull request.
- No new external tools or interpreters (`awk`, `perl`, `python`, ...). The script sticks to
  what it already depends on: `curl`, `grep`, `sed`, `sort`, `wc`, `iprange`. Adding a
  dependency needs to be discussed in an issue first.
- Do not reformat or restructure code unrelated to your change.
- Plain commit messages. No `feat:` / `docs():` prefixes.
