package winsplit

// Before 0.7.1 the kill switch was a set of Windows Firewall rules named
// ksPrefix+ksRules plus the policy "block outbound" on all profiles. Those
// rules are the marker of that old kill switch: only when one of them was
// still there is the policy set back to Windows' default (blockinbound,
// allowoutbound). Without them the policy is the user's (or an admin's) and
// is left alone (report L-07: every enable/disable reset a restrictive
// policy the user had set).

const ksPrefix = "Shunt KS "

var ksRules = []string{"service", "tunnel v4", "tunnel v6", "lan", "dhcp", "dhcp6"} // legacy rule names

// legacyCleanupWith removes the legacy rules with fw (netsh advfirewall
// arguments; nil error = done, so a delete succeeds only when the rule
// existed) and resets the policy only if one existed. It reports whether
// it found any.
func legacyCleanupWith(fw func(args ...string) error) bool {
	found := false
	for _, n := range ksRules {
		if fw("firewall", "delete", "rule", "name="+ksPrefix+n) == nil {
			found = true
		}
	}
	if found {
		_ = fw("set", "allprofiles", "firewallpolicy", "blockinbound,allowoutbound")
	}
	return found
}
