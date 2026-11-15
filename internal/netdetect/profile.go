package netdetect

import "strings"

// Network categories of the Windows Network List Manager
// (NLM_NETWORK_CATEGORY).
const (
	CatPublic  = 0
	CatPrivate = 1
	CatDomain  = 2
)

// ProfileConn is one connected network of the system: the adapter it runs
// on (friendly name, as Info.Iface) and its category.
type ProfileConn struct {
	Adapter  string
	Category int
}

// ProfileName turns an NLM category into "public", "private" or "domain"
// ("" for an unknown value).
func ProfileName(cat int) string {
	switch cat {
	case CatPublic:
		return "public"
	case CatPrivate:
		return "private"
	case CatDomain:
		return "domain"
	}
	return ""
}

// PickProfile chooses the profile of the uplink iface among the connected
// networks. Without a matching adapter it takes the only one there is;
// with several and no match it says nothing (a wrong hint is worse).
func PickProfile(conns []ProfileConn, iface string) string {
	for _, c := range conns {
		if iface != "" && strings.EqualFold(c.Adapter, iface) {
			return ProfileName(c.Category)
		}
	}
	if len(conns) == 1 {
		return ProfileName(conns[0].Category)
	}
	return ""
}

// ClassHint turns the system's rating into a defense class name ("unsafe",
// "unknown"). Only "public" gives a stricter class than the default: the
// user (or Windows) said the network is not theirs. "private" and "domain"
// stay "unknown": only the user may rate a network safe, so this never
// loosens anything. A [[network]] class in the config always wins.
func ClassHint(profile string) string {
	if profile == "public" {
		return "unsafe"
	}
	return "unknown"
}
