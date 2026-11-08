package winsplit

// WifiRandomizationArgs are the netsh arguments that switch Windows' own
// "random hardware addresses" for the Wi-Fi interface iface on or off. The
// setting is per interface (not per network); it applies from the next
// connection. Windows does not offer the same for cable adapters.
func WifiRandomizationArgs(iface string, on bool) []string {
	v := "no"
	if on {
		v = "yes"
	}
	return []string{"wlan", "set", "randomization", "enabled=" + v, "interface=" + iface}
}
