package mobile

import (
	"encoding/json"
	"errors"

	"github.com/Bob-Nixkoenner/the_shunt/internal/mullvad"
)

// Mullvad module. The network calls (login, device, relay list) are made by
// the Kotlin side (Android's own DNS and proxy rules); everything that is
// logic lives here, as pure functions on JSON: keys, server choice, the
// WireGuard file, chains.

// MullvadNormalizeAccount removes spaces and checks the 16-digit number.
func MullvadNormalizeAccount(s string) (string, error) { return mullvad.NormalizeAccount(s) }

// MullvadNewKey makes a WireGuard key pair: {"private":"…","public":"…"}.
func MullvadNewKey() (string, error) {
	priv, pub, err := mullvad.NewKey()
	if err != nil {
		return "", err
	}
	b, _ := json.Marshal(map[string]string{"private": priv, "public": pub})
	return string(b), nil
}

func relayList(relays string) (*mullvad.RelayList, error) {
	var l mullvad.RelayList
	if err := json.Unmarshal([]byte(relays), &l); err != nil {
		return nil, err
	}
	if len(l.WireGuard.Relays) == 0 {
		return nil, errors.New("empty relay list")
	}
	return &l, nil
}

// MullvadCountries turns the public relay list (GET /public/relays/wireguard/v2)
// into the countries and cities with active servers, as JSON.
func MullvadCountries(relays string) (string, error) {
	l, err := relayList(relays)
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(l.Countries())
	return string(b), err
}

type mullvadLogin struct {
	PrivateKey string `json:"private_key"`
	IPv4       string `json:"ipv4"`
	IPv6       string `json:"ipv6"`
}

type mullvadChoice struct {
	Country  string `json:"country"`
	City     string `json:"city"`
	Hostname string `json:"hostname"`
}

// MullvadConf picks a server (choice: {"country":"de","city":"de-fra","hostname":""},
// all empty = any) and builds the wg-quick file for the login
// ({"private_key","ipv4","ipv6"}). hopDepth: how many tunnels this one runs
// through (the MTU gets smaller by 80 per hop). Result: {"conf","hostname",
// "country","city","provider"}.
func MullvadConf(relays, login, choice string, hopDepth int) (string, error) {
	l, err := relayList(relays)
	if err != nil {
		return "", err
	}
	var lg mullvadLogin
	var ch mullvadChoice
	if err := json.Unmarshal([]byte(login), &lg); err != nil {
		return "", err
	}
	if err := json.Unmarshal([]byte(choice), &ch); err != nil {
		return "", err
	}
	r, err := l.Pick(mullvad.Choice{Country: ch.Country, City: ch.City, Hostname: ch.Hostname})
	if err != nil {
		return "", err
	}
	conf, err := mullvad.Conf(lg.PrivateKey, &mullvad.Device{IPv4: lg.IPv4, IPv6: lg.IPv6}, r, l.WireGuard.Gateway, mullvad.HopMTU(hopDepth))
	if err != nil {
		return "", err
	}
	loc := l.Locations[r.Location]
	b, err := json.Marshal(map[string]string{"conf": conf, "hostname": r.Hostname, "country": loc.Country, "city": loc.City, "provider": r.Provider})
	return string(b), err
}

// MullvadChainPick chooses n servers for a chain (2 to 4), each in another
// country and, where possible, at another hosting provider; entry and exit
// are country codes ("" = any). Result: [{"hostname","country","city","provider"}].
func MullvadChainPick(relays string, n int, entry, exit string) (string, error) {
	l, err := relayList(relays)
	if err != nil {
		return "", err
	}
	rs, err := l.PickChain(n, entry, exit)
	if err != nil {
		return "", err
	}
	out := make([]map[string]string, 0, len(rs))
	for _, r := range rs {
		loc := l.Locations[r.Location]
		out = append(out, map[string]string{"hostname": r.Hostname, "country": loc.Country, "city": loc.City, "provider": r.Provider})
	}
	b, err := json.Marshal(out)
	return string(b), err
}
