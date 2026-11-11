package evidence

import "regexp"

var macRe = regexp.MustCompile(`(?i)\b[0-9a-f]{2}([:-])[0-9a-f]{2}(?:[:-][0-9a-f]{2}){4}\b`)
var ssidRe = regexp.MustCompile(`(?i)\b(ssid|bssid|essid|network)=\S+`)

// ScrubDetail removes what must never be in the log from free text: hardware
// (MAC) addresses and SSID/BSSID/network names. The detections write no such
// data today; this is the safety net for those added later.
func ScrubDetail(s string) string {
	s = macRe.ReplaceAllString(s, "<mac>")
	return ssidRe.ReplaceAllString(s, "$1=<removed>")
}
