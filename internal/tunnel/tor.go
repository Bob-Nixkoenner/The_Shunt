package tunnel

// TorSpec describes one Tor tunnel (driver = "tor").
type TorSpec struct {
	Name    string
	DataDir string // /var/lib/shunt/tor/<name>
	RunDir  string // sockets live in RunDir/tor-<name>/
	Bridges []string
	Isolate string // app | destination | none
	// CgroupDir: absolute cgroup directory tor is started in (via `shuntd cgexec`) (its traffic
	// is routed by the group, see engine.Route.TorGroup); "" = ours.
	CgroupDir string
}

// TorStatus is implemented by the Tor device.
type TorStatus interface {
	Bootstrap() int // 0..100
	SocksPath() string
	DNSAddr() string // 127.0.0.1:port, Tor's DNSPort
	NewIdentity() error
	Circuit() *TorCircuit // nil: none yet
}
