module github.com/Bob-Nixkoenner/the_shunt

go 1.26.0

toolchain go1.26.9

require (
	fyne.io/systray v1.12.2
	github.com/BurntSushi/toml v1.6.0
	github.com/florianl/go-nflog/v2 v2.3.0
	github.com/godbus/dbus/v5 v5.2.3
	github.com/google/nftables v0.3.0
	github.com/mdlayher/wifi v0.9.0
	github.com/miekg/dns v1.1.73
	github.com/vishvananda/netlink v1.3.1
	golang.org/x/sys v0.49.0
	golang.org/x/term v0.47.0
	golang.zx2c4.com/wireguard v0.0.0-20261006164505-2631ce99a06f
	golang.zx2c4.com/wireguard/wgctrl v0.0.0-20241231184526-a9ab2273dd10
	gvisor.dev/gvisor v0.0.0-20250503011706-39ed1f5ac29c
)

require (
	github.com/google/btree v1.1.2 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/mdlayher/genetlink v1.4.0 // indirect
	github.com/mdlayher/netlink v1.11.2 // indirect
	github.com/mdlayher/socket v0.7.0 // indirect
	github.com/vishvananda/netns v0.0.5 // indirect
	golang.org/x/crypto v0.58.0 // indirect
	golang.org/x/mobile v0.0.0-20261011034528-197770444867 // indirect
	golang.org/x/mod v0.42.0 // indirect
	golang.org/x/net v0.61.0 // indirect
	golang.org/x/sync v0.24.0 // indirect
	golang.org/x/time v0.7.0 // indirect
	golang.org/x/tools v0.52.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
)

tool (
	golang.org/x/mobile/cmd/gobind
	golang.org/x/mobile/cmd/gomobile
)
