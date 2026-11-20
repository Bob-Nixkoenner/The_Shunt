package winsplit

import (
	"encoding/json"
	"strings"
)

// NCSI boot hold. Windows' connectivity check (NCSI: DNS for
// www.msftconnecttest.com and GET /connecttest.txt) can run in the first
// seconds of a boot, before the base filtering engine (BFE) enforces the kill
// switch; the boot-time copies of the filters did not stop it (lab 13.11.,
// D07/WD05: about 1 s after DHCP, before the first WFP audit event). While
// the kill switch is on, the service sets the NCSI policy NoActiveProbe=1 at
// shutdown, so the next boot does not probe actively, and takes it back once
// it runs again (NCSI then probes through the tunnel and Windows shows
// "Internet" again). The earlier value is saved in the state directory
// before the change; only a value we set is taken back, a policy of the
// administrator is left alone. Uninstalling and "killswitch-off" take it
// back too. Not covered: a hard power-off without a shutdown (no hold set).
//
// Taking the value back is not enough: NlaSvc reads the policy once, when its
// host process loads, and keeps it for the life of that process (lab 20.11.:
// registry value gone and NlaSvc restarted, still no active probe until the
// next boot, so the globe in the tray said "no internet" for the whole
// session; stopping the host process and starting netprofm and NlaSvc again
// brought "Internet" within seconds). After a hold was taken back the service
// therefore restarts that host once the tunnels had time to come up
// (NCSIRestart), but only when nothing else lives in it.
const ncsiPolicyKey = `SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator`

func ncsiValues() []regPrev {
	return []regPrev{{Key: ncsiPolicyKey, Name: "NoActiveProbe", Want: 1}}
}

// onlyNCSIServices reports whether a service host holds nothing but the
// network list services: only then may NCSIRestart stop the process (on some
// Windows builds NlaSvc shares its host with other services, DNS client
// among them, which must not be cut).
func onlyNCSIServices(names []string) bool {
	if len(names) == 0 {
		return false
	}
	for _, n := range names {
		switch strings.ToLower(n) {
		case "nlasvc", "netprofm":
		default:
			return false
		}
	}
	return true
}

// TunnelsReady reads the engine's status JSON and reports whether every
// WireGuard tunnel that is up has had a handshake: the connectivity check
// goes through them, so it is restarted only then (a check that runs before
// the path works finds "no internet" and does not try again by itself).
func TunnelsReady(statusJSON string) bool {
	var st struct {
		Tunnels []struct {
			Type      string `json:"type"`
			Up        bool   `json:"up"`
			Handshake int64  `json:"handshake"`
		} `json:"tunnels"`
	}
	if json.Unmarshal([]byte(statusJSON), &st) != nil {
		return false
	}
	for _, t := range st.Tunnels {
		if t.Type == "wireguard" && t.Up && t.Handshake == 0 {
			return false
		}
	}
	return true
}
