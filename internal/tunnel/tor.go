package tunnel

// TorSpec describes one Tor tunnel (driver = "tor").
type TorSpec struct {
	Name    string
	DataDir string // /var/lib/shunt/tor/<name>
	RunDir  string // sockets live in RunDir/tor-<name>/
	Bridges []string
	Isolate string // app | destination | none
}

// TorStatus is implemented by the Tor device.
type TorStatus interface {
	Bootstrap() int // 0..100
	SocksPath() string
	DNSAddr() string // 127.0.0.1:port, Tor's DNSPort
	NewIdentity() error
}
