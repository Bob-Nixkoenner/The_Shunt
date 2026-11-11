// Package defense watches for attacks on the machine: decoy ports, scan and
// brute-force detection, reputation lists and a "heat" gauge per network.
// It only observes and blocks hostile peers; it never hides who the user is.
//
// Privacy rule: events, reports and logs stay on this machine. Nothing here
// may send them anywhere, and no test or fixture may contain real network
// data (use the documentation ranges 192.0.2.0/24, 198.51.100.0/24,
// 203.0.113.0/24 and 2001:db8::/32).
package defense

import "time"

// Class says how much the user trusts the network they are on.
type Class string

const (
	ClassTrusted Class = "trusted" // e.g. home: decoys off, quiet warnings only
	ClassPublic  Class = "public"  // café, hotel, open guest wifi, unknown: decoys + watching on
	ClassManaged Class = "managed" // employer's internal network: watch only, no decoys
)

// Valid reports whether c is a known class.
func (c Class) Valid() bool {
	return c == ClassTrusted || c == ClassPublic || c == ClassManaged
}

// Normalize turns an empty or unknown class into ClassPublic: only what the
// user marked as trusted is trusted.
func (c Class) Normalize() Class {
	if c.Valid() {
		return c
	}
	return ClassPublic
}

// Decoys reports whether decoy listeners may run in this class.
func (c Class) Decoys() bool { return c.Normalize() == ClassPublic }

// Kind names what happened.
type Kind string

const (
	KindDecoyHit    Kind = "decoy_hit"   // someone connected to a decoy port
	KindTarpit      Kind = "tarpit"      // a peer is being held in the tarpit
	KindCowrie      Kind = "cowrie"      // login attempt on the fake service
	KindScan        Kind = "scan"        // many ports from one source
	KindBruteForce  Kind = "brute_force" // many failed connections
	KindReputation  Kind = "reputation"  // peer or destination on a bad list
	KindFirstSeen   Kind = "first_seen"  // an app contacted a new destination
	KindARP         Kind = "arp"         // gateway MAC changed / ARP or NDP spoofing
	KindRogueDHCP   Kind = "rogue_dhcp"  // second DHCP server answered
	KindDNSHijack   Kind = "dns_hijack"  // DNS answers differ or port 53 is diverted
	KindTLS         Kind = "tls"         // certificate of a known target changed
	KindBeacon      Kind = "beacon"      // regular-interval traffic
	KindDNSTunnel   Kind = "dns_tunnel"  // long/random names, many TXT queries
	KindEvilTwin    Kind = "evil_twin"   // same SSID, different BSSID/gateway
	KindBan         Kind = "ban"         // a source was blocked
	KindManual      Kind = "manual"      // ban reason: the user blocked it
	KindUnban       Kind = "unban"       // a block was lifted
	KindNetEnter    Kind = "net_enter"   // network joined (class in Detail)
	KindObservation Kind = "observation" // passive finding (broadcast chatter, captive portal, ...)
	KindExposed     Kind = "exposed"     // the uplink has a public address: directly reachable from the internet
	KindOutside     Kind = "outside"     // result of the outside check (ports that answer from the internet)
)

// Severity of an event. It feeds the heat gauge.
type Severity int

const (
	SevInfo Severity = iota
	SevLow
	SevMedium
	SevHigh
)

// Event is one thing the defense saw. Src is the remote address (never a
// local one); Detail is free text without personal data.
type Event struct {
	Seq      uint64    `json:"seq"` // grows by one per event, starts at 1
	Time     time.Time `json:"time"`
	Kind     Kind      `json:"kind"`
	Severity Severity  `json:"severity"`
	Src      string    `json:"src,omitempty"`  // remote IP, no port
	Port     int       `json:"port,omitempty"` // local port that was hit, if any
	Proto    string    `json:"proto,omitempty"`
	Detail   string    `json:"detail,omitempty"`
}

// Level is the coarse reading of the heat gauge.
type Level string

const (
	LevelQuiet   Level = "quiet"   // 0-24
	LevelNoticed Level = "noticed" // 25-49
	LevelHot     Level = "hot"     // 50-79
	LevelAttack  Level = "attack"  // 80-100
)

// LevelFor maps a heat value (0-100) to its level.
func LevelFor(heat int) Level {
	switch {
	case heat >= 80:
		return LevelAttack
	case heat >= 50:
		return LevelHot
	case heat >= 25:
		return LevelNoticed
	}
	return LevelQuiet
}

// Feature names, used as keys in Config.Features and in the UI.
const (
	FeatDecoy      = "decoy"
	FeatTarpit     = "tarpit"
	FeatCowrie     = "cowrie"
	FeatScan       = "scan"
	FeatBrute      = "brute"
	FeatReputation = "reputation"
	FeatFirstSeen  = "first_seen"
	FeatARP        = "arp"
	FeatDHCP       = "dhcp"
	FeatDNS        = "dns"
	FeatTLS        = "tls"
	FeatBeacon     = "beacon"
	FeatDNSTunnel  = "dns_tunnel"
	FeatEvilTwin   = "evil_twin"
)

// AllFeatures lists every feature in display order.
var AllFeatures = []string{
	FeatDecoy, FeatTarpit, FeatCowrie, FeatScan, FeatBrute, FeatReputation,
	FeatFirstSeen, FeatARP, FeatDHCP, FeatDNS, FeatTLS, FeatBeacon,
	FeatDNSTunnel, FeatEvilTwin,
}

// Feature is one switch: watch (detect and report) and block (act on it).
// Blocking without watching makes no sense; the manager treats Block as off
// when Watch is off.
type Feature struct {
	Watch bool `json:"watch" toml:"watch"`
	Block bool `json:"block" toml:"block"`
}

// Config is the [defense] section. The zero value is "off".
type Config struct {
	Enabled  bool               `json:"enabled" toml:"enabled"`
	Features map[string]Feature `json:"features" toml:"features"`
	// DecoyPorts are the TCP ports the decoys listen on in public networks.
	// Ports that something else already listens on are skipped.
	DecoyPorts []int `json:"decoy_ports" toml:"decoy_ports"`
	// BanSeconds is how long a source stays blocked (default 3600).
	BanSeconds int `json:"ban_seconds" toml:"ban_seconds"`
	// Never lists addresses/CIDRs that are never blocked (gateway, DNS and
	// captive portal are added automatically at runtime).
	Never []string `json:"never" toml:"never"`
	// ReputationSources names optional downloadable lists ("sslbl_ja3",
	// "et_compromised"). Empty = only the built-in CC0 lists. Nothing
	// optional is fetched unless the user lists it here.
	ReputationSources []string `json:"reputation_sources" toml:"reputation_sources"`
	// ReputationOff names built-in lists ("feodo", "sslbl") the user
	// switched off. Empty = both run.
	ReputationOff []string `json:"reputation_off" toml:"reputation_off"`
	// TLSTargets are the public sites whose certificate chain the tls
	// feature checks (host names, at most 16). Empty = api.github.com and
	// www.wikipedia.org.
	TLSTargets []string `json:"tls_targets,omitempty" toml:"tls_targets,omitempty"`
	// DHCPProbe says whether the dhcp feature may send its active DISCOVER
	// probe: "auto" (default, "" too) = only in public networks and never
	// while the quiet mode is on, "on" = always, "off" = never (listen only).
	DHCPProbe string `json:"dhcp_probe,omitempty" toml:"dhcp_probe,omitempty"`
	// DNSProbe is the same switch for the active DNS check (queries to the
	// network's resolvers and to a public resolver outside the tunnel).
	DNSProbe string `json:"dns_probe,omitempty" toml:"dns_probe,omitempty"`
	// DecoysWhenExposed lets the decoys run although the uplink has a public
	// address (default false: a decoy there is real attack surface).
	DecoysWhenExposed bool `json:"decoys_when_exposed,omitempty" toml:"decoys_when_exposed,omitempty"`
	// OutsideScan configures the check from outside against your own server.
	OutsideScan OutsideScanConfig `json:"outside_scan" toml:"outside_scan"`
}

// OutsideScanConfig is [defense.outside_scan]: a server of your own (see
// tools/outside-scan.sh) that connects back to this machine's public
// address and reports which ports answer. Off by default; it can only ever
// be asked about the address the request came from.
type OutsideScanConfig struct {
	Enabled bool `json:"enabled" toml:"enabled"`
	// Host is the https:// (or http:// on a trusted path) URL of the check
	// endpoint, e.g. "https://scan.example.net/outside-scan".
	Host string `json:"host,omitempty" toml:"host,omitempty"`
	// Token is the shared secret the endpoint expects (header X-Shunt-Token).
	Token string `json:"token,omitempty" toml:"token,omitempty"`
}

// DHCP probe modes.
const (
	ProbeAuto = "auto"
	ProbeOn   = "on"
	ProbeOff  = "off"
)

// ValidProbeMode reports whether m is a known dhcp_probe value ("" = auto).
func ValidProbeMode(m string) bool {
	return m == "" || m == ProbeAuto || m == ProbeOn || m == ProbeOff
}

// ProbeAllowed decides whether the active DHCP probe may be sent: auto only
// in public networks and not while the quiet mode is on, on always, off never.
func ProbeAllowed(mode string, class Class, quiet bool) bool {
	switch mode {
	case ProbeOn:
		return true
	case ProbeOff:
		return false
	}
	return class.Normalize() == ClassPublic && !quiet
}

// DefaultConfig: detection on, blocking off, decoys on common ports. Off
// until Enabled is set (the Opsec level sets it).
func DefaultConfig() Config {
	f := map[string]Feature{}
	for _, n := range AllFeatures {
		f[n] = Feature{Watch: true}
	}
	return Config{
		Features:   f,
		DecoyPorts: []int{22, 23, 2222, 2323, 80, 443, 445, 3389},
		BanSeconds: 3600,
		DHCPProbe:  ProbeAuto,
		DNSProbe:   ProbeAuto,
	}
}

// Ban is one blocked source.
type Ban struct {
	Src     string    `json:"src"`
	Reason  Kind      `json:"reason"`
	Since   time.Time `json:"since"`
	Expires time.Time `json:"expires"`
}

// Exposure says whether the uplink has a public address. It is a trait on
// top of the class: a trusted network at home can have one too.
type Exposure struct {
	V4 bool `json:"v4"`
	V6 bool `json:"v6"`
	// Inbound is the incoming protection in effect on this network:
	// "closed", "lan", "open" or "off" (The Shunt does not filter).
	Inbound string `json:"inbound,omitempty"`
}

// Any reports whether either family is public.
func (e Exposure) Any() bool { return e.V4 || e.V6 }

// Status is what /v1/defense returns.
type Status struct {
	Enabled bool         `json:"enabled"`
	Class   Class        `json:"class"`
	Exposed Exposure     `json:"exposed"`
	Heat    int          `json:"heat"` // 0-100
	Level   Level        `json:"level"`
	Decoys  []int        `json:"decoys"` // ports currently listening
	Bans    []Ban        `json:"bans"`
	Counts  map[Kind]int `json:"counts"` // events per kind since the network was joined
	LastSeq uint64       `json:"last_seq"`
	Config  Config       `json:"config"`
	// Sources is the state of every list (also the ones that are off).
	Sources []SourceInfo `json:"sources"`
	// Outside is the last outside check (nil = none yet).
	Outside *OutsideResult `json:"outside,omitempty"`
	// Unsupported is set when this platform lacks parts (reason text).
	Unsupported string `json:"unsupported,omitempty"`
}

// SourceInfo is the status of one reputation list.
type SourceInfo struct {
	Name    string    `json:"name"`
	On      bool      `json:"on"`
	Entries int       `json:"entries"`
	Updated time.Time `json:"updated,omitzero"`
	Error   string    `json:"error,omitempty"`
	// Expired: too old (or never downloaded), so it no longer matches.
	Expired bool `json:"expired,omitempty"`
	// Quality: the list may block; other lists only report.
	Quality bool `json:"quality,omitempty"`
	// Unavailable: documented, but the terms of use forbid building it in.
	Unavailable bool `json:"unavailable,omitempty"`
}

// EventsResponse is what /v1/defense/events?since=N returns: events with
// Seq > N (at most 200, oldest first).
type EventsResponse struct {
	Events  []Event `json:"events"`
	LastSeq uint64  `json:"last_seq"`
}

// Engine is what the daemon, the API and the UI talk to. Implemented by
// *Manager (package defense); tests and the UI mock implement it too.
type Engine interface {
	// SetNetwork tells the engine which network the machine is in now.
	// key identifies the network locally (never logged or sent anywhere).
	SetNetwork(key string, class Class)
	// SetExposure tells the engine whether the uplink has a public address.
	SetExposure(e Exposure)
	// SetOutside records an outside-check result.
	SetOutside(r OutsideResult)
	Configure(cfg Config)
	Status() Status
	Events(since uint64) EventsResponse
	// EventsFor returns every kept event of one source address.
	EventsFor(src string) EventsResponse
	// Reports returns the local per-network reports (export = redacted).
	Reports(export bool) ReportsResponse
	// Unban lifts one block ("" = all).
	Unban(src string)
	// Ban blocks one address by hand (refused for the never-list and when
	// the defense is off).
	Ban(src string) error
	// Report adds an event from outside (sniffers, DNS proxy, ...).
	Report(ev Event)
	Close()
}
