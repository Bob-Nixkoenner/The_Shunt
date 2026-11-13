package winsplit

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
const ncsiPolicyKey = `SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator`

func ncsiValues() []regPrev {
	return []regPrev{{Key: ncsiPolicyKey, Name: "NoActiveProbe", Want: 1}}
}
