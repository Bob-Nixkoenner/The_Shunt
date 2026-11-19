# Mullvad module

Log in with a Mullvad account number, pick a server, get an ordinary WireGuard tunnel. Linux desktop and Android (Windows follows).

## What it does

- **Login:** the app makes its own WireGuard key and registers it as a *device* of the account (`POST /auth/v1/token`, `POST /accounts/v1/devices`). Mullvad allows 5 devices per account; logging out deletes the device again (`DELETE /accounts/v1/devices/{id}`). One login is one device, however many tunnels use it.
- **Several logins:** each has a name (`main` if none); every Mullvad tunnel names its login, so the hops of a chain can use different accounts (and keys).
- **Exit choice:** from the public relay list (`GET /public/relays/wireguard/v2`, no login needed): any server, a country, a city or one server. Switching the exit of an existing tunnel swaps its file in place; rules and routes stay.
- **Chains:** 2 to 4 tunnels, each running through the one before (`via`), every hop in another country and, where the list allows, at another hosting provider. MTU: 1420 minus 80 per hop, at least 1280. Tunnels are named `NAME1` (entry) … `NAMEn` (exit); rules use the last one. A failed hop removes the ones made.
- **Logout** removes the login's tunnels (a chain from the outside in), then the device. A tunnel that a rule or another tunnel still uses stops it with a message.

## Where things are

| | Linux desktop | Android |
|---|---|---|
| Logic (keys, server choice, file, chains) | `internal/mullvad` | the same package, through `mobile/mullvad.go` |
| Network calls | the daemon (`internal/daemon/mullvad.go`) | the app (`Mullvad.kt`, Android DNS) |
| Secrets | `/etc/shunt/mullvad.json`, mode 600 | sealed in the key store inside `settings.json` |
| UI | Configure > Add a tunnel > Mullvad | Tunnels tab > Mullvad |
| API | `GET /v1/mullvad`, `GET /v1/mullvad/relays`, `POST /v1/mullvad/{login,connect,chain,chain/delete,logout}` | – |

The account number and the key never go to the UI, a log or the core's config. The only address the module contacts is `api.mullvad.net`, and only while it is used (named in the privacy pages and the Android first-start text).

## Limits

- A chain through tunnels of one login gives Mullvad the same key at every hop; with one login the chain builder says so. Several accounts (paid anonymously) give each hop its own key. Mullvad stays one operator: for real spread add a tunnel of another provider to the chain.
- Every hop costs about 100 ms and a share of the bandwidth. Some server pairs have a bad path (seen: one hop with a fraction of the normal upload); delete the chain and build it again.
