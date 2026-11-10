package winsplit

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
)

// Disguise on Windows (daemon.dhcp_hostname, daemon.mac), measured in the lab:
//
//   - Option 81 (DHCPv4 FQDN) and the DHCPv6 FQDN option follow the per
//     interface value RegistrationEnabled ("register this connection's
//     addresses in DNS"): 0 drops both, live.
//   - Option 12 (host name) and the DHCPv6 DUID (a DUID-LLT with the real
//     MAC) are read by the DHCP client service once, when it starts; a change
//     in the registry only shows after the next boot, and the service cannot
//     be restarted (WinHTTP auto proxy depends on it and refuses to stop). So
//     at system shutdown neutral values are written, the next boot's DHCP
//     client reads them, and this service puts the real ones back once it is
//     up (the running DHCP client keeps what it read).
//   - NetworkAddress (cable adapters) is read when the adapter starts: the
//     adapter is restarted when it changes; random values are chosen at
//     shutdown for the next boot, so the boot itself needs no restart.
//
// Every value changed is saved first (state file) and put back when the mode
// ends, at the next start after a crash, and on uninstall.

const (
	nicClassKey  = `SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}`
	netConnKey   = `SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}`
	tcpipParams  = `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`
	tcpip6Params = `SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters`
	// Windows interface types (*IfType): Ethernet and Wi-Fi.
	nicEthernet = 6
	nicWifi     = 71
)

// RegVal is one registry value (dword, string or binary).
type RegVal struct {
	Kind string `json:"k"` // "dword" | "sz" | "bin"
	D    uint32 `json:"d,omitempty"`
	S    string `json:"s,omitempty"`
	B    []byte `json:"b,omitempty"`
}

func (v RegVal) equal(o RegVal) bool {
	return v.Kind == o.Kind && v.D == o.D && v.S == o.S && bytes.Equal(v.B, o.B)
}

// ValReg is the registry access (HKLM) the disguise needs.
type ValReg interface {
	Get(key, name string) (RegVal, bool, error)
	Set(key, name string, v RegVal) error
	Delete(key, name string) error
	SubKeys(key string) ([]string, error)
}

// Override is a value we changed: the earlier content and what we wrote.
type Override struct {
	Key     string `json:"key"`
	Name    string `json:"name"`
	Existed bool   `json:"existed"`
	Orig    RegVal `json:"orig"`
	Ours    RegVal `json:"ours"`
	Boot    bool   `json:"boot,omitempty"` // written at shutdown for the next boot; put back at the next start
}

// TarnState is the saved state of the disguise.
type TarnState struct {
	Secret    string     `json:"secret"` // for the stable MAC addresses
	Overrides []Override `json:"overrides,omitempty"`
}

// NIC is a network adapter as the registry's adapter class lists it.
type NIC struct {
	Sub    string // 0001
	GUID   string // {....}
	Desc   string
	DevID  string // DeviceInstanceID
	IfType uint32
	Conn   string // name in the network connections ("Ethernet")
}

// Hardware: a real or virtual NIC on the PCI/USB bus (not VPN, loopback or
// software adapters, which use ROOT\ or SWD\).
func (n NIC) Hardware() bool {
	d := strings.ToUpper(n.DevID)
	return strings.HasPrefix(d, `PCI\`) || strings.HasPrefix(d, `USB\`)
}

// Cable: an Ethernet adapter we may give another MAC (Wi-Fi has Windows' own
// setting).
func (n NIC) Cable() bool { return n.Hardware() && n.IfType == nicEthernet && n.Conn != tunnelConnName }

// Registers: adapters whose DNS registration (DHCP FQDN) we switch off.
func (n NIC) Registers() bool {
	return n.Hardware() && (n.IfType == nicEthernet || n.IfType == nicWifi) && n.Conn != tunnelConnName
}

func isSub(s string) bool {
	if len(s) != 4 {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// ListNICs reads the adapters from the registry.
func ListNICs(r ValReg) []NIC {
	subs, _ := r.SubKeys(nicClassKey)
	var out []NIC
	for _, s := range subs {
		if !isSub(s) {
			continue
		}
		k := nicClassKey + `\` + s
		str := func(n string) string { v, _, _ := r.Get(k, n); return v.S }
		n := NIC{Sub: s, GUID: str("NetCfgInstanceId"), Desc: str("DriverDesc"), DevID: str("DeviceInstanceID")}
		if v, ok, _ := r.Get(k, "*IfType"); ok {
			n.IfType = v.D
		}
		if n.GUID == "" {
			continue
		}
		if v, ok, _ := r.Get(netConnKey+`\`+n.GUID+`\Connection`, "Name"); ok {
			n.Conn = v.S
		}
		out = append(out, n)
	}
	return out
}

// Want is what the config asks for on the current network.
type Want struct {
	HideName bool   // dhcp_hostname = none
	MAC      string // random | stable | permanent | ""
}

// WantFor decides by daemon.* and the profile of the network we are on
// ("" = none recognised).
func WantFor(c *config.Config, network string) Want {
	if c == nil {
		return Want{}
	}
	host, mac := c.Daemon.DHCPHostname, c.Daemon.MAC
	if network != "" {
		for _, n := range c.Networks {
			if n.Name == network {
				if n.DHCPHostname != "" {
					host = n.DHCPHostname
				}
				if n.MAC != "" {
					mac = n.MAC
				}
			}
		}
	}
	return Want{HideName: host == config.HostnameNone, MAC: mac}
}

// BootWant is Want for the next boot (the network is not known yet): the
// daemon defaults.
func BootWant(c *config.Config) Want { return WantFor(c, "") }

// NeutralHostname returns a name like Windows' own default ("DESKTOP-4F8K2QX").
func NeutralHostname(r io.Reader) string {
	const al = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 7)
	_, _ = io.ReadFull(r, b)
	var sb strings.Builder
	sb.WriteString("DESKTOP-")
	for _, x := range b {
		sb.WriteByte(al[int(x)%len(al)])
	}
	return sb.String()
}

// macFrom shapes six bytes into a locally administered unicast address.
func macFrom(b []byte) string {
	m := append([]byte(nil), b[:6]...)
	m[0] = m[0]&0xfc | 0x02
	return strings.ToUpper(hex.EncodeToString(m))
}

// RandomMAC returns 12 hex digits (the registry form), locally administered.
func RandomMAC(r io.Reader) string {
	b := make([]byte, 6)
	_, _ = io.ReadFull(r, b)
	return macFrom(b)
}

// StableMAC derives the address of one adapter from the machine's secret: the
// same every time, different on every machine.
func StableMAC(secret, guid string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte("shunt-mac|" + strings.ToLower(guid)))
	return macFrom(h.Sum(nil))
}

// ValidMAC: 12 hex digits, locally administered unicast (what Windows accepts
// for NetworkAddress).
func ValidMAC(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == 6 && b[0]&0x01 == 0 && b[0]&0x02 != 0
}

// NeutralDUID is a DUID-LL (type 3, Ethernet) for the MAC in the registry
// form: Windows' own DUID-LLT carries the real hardware address.
func NeutralDUID(mac string) []byte {
	b, _ := hex.DecodeString(mac)
	return append([]byte{0, 3, 0, 1}, b...)
}

// Tarn applies the disguise to the registry and keeps the saved state.
type Tarn struct {
	mu      sync.Mutex
	Reg     ValReg
	File    string
	Rand    io.Reader
	Restart func(conn string) error // restarts an adapter (nil = not at all)
}

func NewTarn(r ValReg, file string, restart func(string) error) *Tarn {
	return &Tarn{Reg: r, File: file, Rand: rand.Reader, Restart: restart}
}

func (t *Tarn) load() *TarnState {
	s := &TarnState{}
	if b, err := os.ReadFile(t.File); err == nil {
		_ = json.Unmarshal(b, s)
	}
	if s.Secret == "" {
		b := make([]byte, 16)
		_, _ = io.ReadFull(t.Rand, b)
		s.Secret = hex.EncodeToString(b)
	}
	return s
}

func (t *Tarn) save(s *TarnState) error {
	if err := os.MkdirAll(filepath.Dir(t.File), 0o755); err != nil {
		return err
	}
	b, _ := json.Marshal(s)
	tmp := t.File + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	// Windows refuses to rename over a file that something (virus scanner,
	// indexer) has open for a moment: try again, then write in place
	var err error
	for i := 0; i < 5; i++ {
		if err = os.Rename(tmp, t.File); err == nil {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	_ = os.Remove(tmp)
	return os.WriteFile(t.File, b, 0o600)
}

func (s *TarnState) find(key, name string) int {
	for i, o := range s.Overrides {
		if o.Key == key && o.Name == name {
			return i
		}
	}
	return -1
}

// set makes the value want (saving the earlier one first); true = changed.
func (t *Tarn) set(s *TarnState, key, name string, want RegVal, boot bool) (bool, error) {
	cur, ok, err := t.Reg.Get(key, name)
	if err != nil {
		return false, err
	}
	i := s.find(key, name)
	if ok && cur.equal(want) {
		if i >= 0 {
			s.Overrides[i].Ours, s.Overrides[i].Boot = want, boot
		}
		return false, nil
	}
	if i < 0 || !ok || !cur.equal(s.Overrides[i].Ours) {
		// first change, or somebody else changed it since: take the present value as the original
		o := Override{Key: key, Name: name, Existed: ok, Orig: cur, Ours: want, Boot: boot}
		if i >= 0 {
			s.Overrides[i] = o
		} else {
			s.Overrides = append(s.Overrides, o)
			i = len(s.Overrides) - 1
		}
	} else {
		s.Overrides[i].Ours, s.Overrides[i].Boot = want, boot
	}
	if err := t.save(s); err != nil { // save before changing
		return false, err
	}
	return true, t.Reg.Set(key, name, want)
}

// release puts the original back if the value still is ours; true = changed.
func (t *Tarn) release(s *TarnState, i int) (bool, error) {
	o := s.Overrides[i]
	cur, ok, err := t.Reg.Get(o.Key, o.Name)
	if err != nil {
		return false, err
	}
	changed := false
	if ok && cur.equal(o.Ours) {
		if o.Existed {
			err = t.Reg.Set(o.Key, o.Name, o.Orig)
		} else {
			err = t.Reg.Delete(o.Key, o.Name)
		}
		if err != nil {
			return false, err
		}
		changed = true
	}
	s.Overrides = append(s.Overrides[:i], s.Overrides[i+1:]...)
	return changed, t.save(s)
}

func (t *Tarn) releaseWhere(s *TarnState, match func(Override) bool) (changedNames []string, err error) {
	for i := 0; i < len(s.Overrides); {
		o := s.Overrides[i]
		if !match(o) {
			i++
			continue
		}
		ch, e := t.release(s, i)
		if e != nil {
			if err == nil {
				err = e
			}
			i++
			continue
		}
		if ch {
			changedNames = append(changedNames, o.Key)
		}
	}
	return
}

func ifaceKey(guid string) string { return tcpipParams + `\Interfaces\` + guid }

func nicKey(sub string) string { return nicClassKey + `\` + sub }

func (t *Tarn) restartAll(convs map[string]bool) {
	if t.Restart == nil {
		return
	}
	for c := range convs {
		_ = t.Restart(c)
	}
}

// Apply brings the live registry in line with w: DNS registration (DHCP FQDN)
// and the cable adapters' MAC. It returns the adapters it restarted.
func (t *Tarn) Apply(w Want) (restarted []string, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.load()
	restart := map[string]bool{}
	var first error
	keep := func(e error) {
		if e != nil && first == nil {
			first = e
		}
	}
	nics := ListNICs(t.Reg)
	// DHCP FQDN options (live)
	for _, n := range nics {
		if !n.Registers() {
			continue
		}
		k := ifaceKey(n.GUID)
		if w.HideName {
			_, e := t.set(s, k, "RegistrationEnabled", RegVal{Kind: "dword", D: 0}, false)
			keep(e)
		} else if i := s.find(k, "RegistrationEnabled"); i >= 0 {
			_, e := t.release(s, i)
			keep(e)
		}
	}
	// MAC of the cable adapters
	for _, n := range nics {
		if !n.Cable() {
			continue
		}
		k := nicKey(n.Sub)
		var want string
		switch w.MAC {
		case config.MACRandom:
			if i := s.find(k, "NetworkAddress"); i >= 0 && ValidMAC(s.Overrides[i].Ours.S) {
				if cur, ok, _ := t.Reg.Get(k, "NetworkAddress"); ok && cur.equal(s.Overrides[i].Ours) {
					want = cur.S // chosen at shutdown or earlier: keep for this boot
				}
			}
			if want == "" {
				want = RandomMAC(t.Rand)
			}
		case config.MACStable:
			want = StableMAC(s.Secret, n.GUID)
		}
		if want != "" {
			ch, e := t.set(s, k, "NetworkAddress", RegVal{Kind: "sz", S: want}, false)
			keep(e)
			if ch {
				restart[n.Conn] = true
			}
		} else if i := s.find(k, "NetworkAddress"); i >= 0 {
			ch, e := t.release(s, i)
			keep(e)
			if ch {
				restart[n.Conn] = true
			}
		}
	}
	keep(t.save(s))
	t.restartAll(restart)
	for c := range restart {
		restarted = append(restarted, c)
	}
	return restarted, first
}

// PrepareShutdown writes what the next boot's DHCP client should read: a
// neutral host name and DUID (put back by RestoreBoot) and, for random MACs,
// a fresh address. Call it when the system shuts down.
func (t *Tarn) PrepareShutdown(w Want) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.load()
	var first error
	keep := func(_ bool, e error) {
		if e != nil && first == nil {
			first = e
		}
	}
	mac := ""
	if w.MAC == config.MACRandom {
		for _, n := range ListNICs(t.Reg) {
			if !n.Cable() {
				continue
			}
			m := RandomMAC(t.Rand)
			if mac == "" {
				mac = m
			}
			keep(t.set(s, nicKey(n.Sub), "NetworkAddress", RegVal{Kind: "sz", S: m}, false))
		}
	}
	if w.HideName {
		name := NeutralHostname(t.Rand)
		keep(t.set(s, tcpipParams, "Hostname", RegVal{Kind: "sz", S: name}, true))
		keep(t.set(s, tcpipParams, "NV Hostname", RegVal{Kind: "sz", S: name}, true))
		if mac == "" {
			mac = RandomMAC(t.Rand)
		}
		keep(t.set(s, tcpip6Params, "Dhcpv6DUID", RegVal{Kind: "bin", B: NeutralDUID(mac)}, true))
	}
	keep(false, t.save(s))
	return first
}

// RestoreBoot puts the real host name and DUID back (the DHCP client has read
// the neutral ones by now). Call it once the network is up, and at every
// start: after a crash the values written at shutdown are still there.
func (t *Tarn) RestoreBoot() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.load()
	_, err := t.releaseWhere(s, func(o Override) bool { return o.Boot })
	return err
}

// RestoreAll puts everything back (uninstall) and restarts adapters whose MAC
// changed.
func (t *Tarn) RestoreAll() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.load()
	conns := map[string]string{} // nic key -> connection
	for _, n := range ListNICs(t.Reg) {
		conns[nicKey(n.Sub)] = n.Conn
	}
	changed, err := t.releaseWhere(s, func(Override) bool { return true })
	restart := map[string]bool{}
	for _, k := range changed {
		if c := conns[k]; c != "" {
			restart[c] = true
		}
	}
	t.restartAll(restart)
	return err
}

// tunnelConnName is the Shunt adapter's connection name (AdapterName on
// Windows): never touched.
var tunnelConnName = "Shunt"
