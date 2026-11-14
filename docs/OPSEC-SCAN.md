# Opsec scan

`tools/opsec-scan.sh` looks for private data that must not be public:
e-mail addresses, real IPv4 addresses (outside the documentation ranges),
MAC addresses, `/home/<user>` paths, tokens/keys, and, from a local file,
any extra private strings (real names, device names, network names, lab IPs).

The output is masked: it prints only `file:line [kind]` (history mode:
`commit:file [kind]`), never the matched value. Exit code 1 means findings.

## When to run

- before every release candidate and before every push to GitHub
- after any history cleanup (rewrite, filter-repo, mailmap change): with `--history`
- after merging branches from lab or test machines
- once after changing the allowlist

## How

    tools/opsec-scan.sh              # work tree (tracked files)
    tools/opsec-scan.sh --history    # plus all commits, authors, committers, tags (slow)
    tools/opsec-scan.sh --no-private # generic patterns only (what CI can do)
    tools/opsec-scan.sh --path DIR   # scan another clone
    tools/opsec-scan-test.sh         # self test

Kinds: `email`, `ipv4` (public), `ipv4-private` (10/8, 172.16/12, 192.168/16,
100.64/10), `mac`, `home`, `token`, `wgkey` (WireGuard-style base64 key),
`private` (local pattern file).

## Private patterns (local only)

`OPSEC_PATTERNS` points to a local file. Default:
`~/projects/shunt-lab-results/ersetzen.txt`. It is never part of the repo.
Format, one per line: `LITERAL==>replacement` or `regex:PCRE==>replacement`
(only the left side is used for matching). `OPSEC_MAILMAP` (default: `mailmap.txt`
next to it) lists private mail addresses; the last `<address>` of each line is
searched for as well. Without the file the scan runs generic-only and says so.

## Allowlist

`tools/opsec-allow.txt` holds regexes (one per line, whole-value match, case
insensitive) for values that are fine: placeholder mails, documentation IP
ranges, public DNS servers, systemd unit names. Only placeholders belong
there, never real values. Test fixtures with 10.x lab addresses show up as
`ipv4-private`; either replace them with documentation ranges or accept them
knowingly. A real finding is fixed in the source, not allowlisted.

## Fixing findings

- work tree: replace the value with a placeholder (`example.org`, `203.0.113.x`)
- history: rewrite (git filter-repo with a replace-text file and mailmap), then
  force push, then re-run with `--history`
- GitHub-only text (PR/issue bodies, release notes, tag annotations): edit there;
  GitHub keeps old revisions of edited PR texts only for the author, but cached
  views and forks keep old content, so for mail addresses ask GitHub support to
  purge cached views if needed

## CI proposal (not enabled)

Only the generic part, no private patterns (the pattern file is not in the repo):

    name: opsec-scan
    on: [pull_request]
    jobs:
      scan:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@v4
          - run: tools/opsec-scan.sh --no-private

Expect to tune the allowlist first: lab fixtures with private IPs would fail it.
