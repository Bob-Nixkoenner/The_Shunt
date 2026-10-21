<!-- generated from dnslists/defaults.toml - do not edit; run: go test ./dnslists -update -->
# Default DNS filter lists

These are the blocklists The Shunt uses out of the box. The levels build on each other:
**Normal** = Low + its own lists, **Paranoid** = Normal + its own lists.
Default level: **Normal** (2).

**Something missing, too much, or in the wrong level?** Open an issue or a pull request that edits
[`dnslists/defaults.toml`](../dnslists/defaults.toml) – this page is generated from it.
Lists come from [RPiList/specials](https://github.com/RPiList/specials/tree/master/Blocklisten) and from
[HaGeZi's DNS blocklists](https://github.com/hagezi/dns-blocklists) (GPL-3.0; the `hagezi:` ones) - many thanks to both projects.
They are downloaded when used and are not part of The Shunt. HaGeZi's Light, Pro and Pro++ build on each other (each
contains the one before); the levels still use a bigger one each, which keeps Low small and costs only a little overlap.

## Level 1 – Low

| List | What it blocks | Only on |
|---|---|---|
| [hagezi:light](https://github.com/hagezi/dns-blocklists) | HaGeZi Multi LIGHT: basic protection against ads, trackers and telemetry, hardly ever breaks anything |  |
| [hagezi:tif.mini](https://github.com/hagezi/dns-blocklists) | HaGeZi Threat Intelligence (mini): malware, phishing and command-and-control hosts |  |
| `Phishing-Angriffe` | Phishing sites |  |
| `malware` | Known malware hosts |  |
| `Corona-Blocklist` | Scam and fake-shop sites that used the pandemic |  |
| `SupportingRussia` | Sites supporting the Russian war of aggression |  |

## Level 2 – Normal

| List | What it blocks | Only on |
|---|---|---|
| [hagezi:pro](https://github.com/hagezi/dns-blocklists) | HaGeZi Multi PRO: extended protection against ads, trackers, telemetry, scams and cryptojacking (the maintainer's recommendation) |  |
| `notserious` | Fake shops and dubious offers |  |
| `Fake-Science` | Fake science and misinformation sites |  |
| `spam.mails` | Domains seen in spam mails |  |
| `crypto` | Cryptojacking and crypto scams |  |
| `Win10Telemetry` | Windows 10 telemetry | windows |
| `MS-Office-Telemetry` | Microsoft Office telemetry | windows |

## Level 3 – Paranoid

| List | What it blocks | Only on |
|---|---|---|
| [hagezi:pro.plus](https://github.com/hagezi/dns-blocklists) | HaGeZi Multi PRO++: more aggressive than PRO, some sites may need an allow entry |  |
| `gambling` | Gambling and betting |  |
| `Streaming` | Streaming sites |  |
| `DatingSites` | Dating sites |  |
| `child-protection` | Child protection |  |
| `proxies` | Public proxies and anonymizers |  |
| `DomainSquatting1` | Domain squatting, part 1 |  |
| `DomainSquatting2` | Domain squatting, part 2 |  |
| `DomainSquatting3` | Domain squatting, part 3 |  |
| `DomainSquatting4` | Domain squatting, part 4 |  |
| `pornblock1` | Adult content, part 1 |  |
| `pornblock2` | Adult content, part 2 |  |
| `pornblock3` | Adult content, part 3 |  |
| `pornblock4` | Adult content, part 4 |  |
| `pornblock5` | Adult content, part 5 |  |
| `pornblock6` | Adult content, part 6 |  |
| `Overblock` | Very broad list - blocks a lot, expect breakage |  |
