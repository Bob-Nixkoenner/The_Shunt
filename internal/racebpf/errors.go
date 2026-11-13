package racebpf

import "errors"

// ErrNoCaps: shuntd may not use bpf() at all (neither CAP_BPF nor
// CAP_SYS_ADMIN in its effective set, e.g. a service file or a wrapper that
// cut the bounding set). The kernel then answers every map with EPERM,
// which cilium/ebpf words as "MEMLOCK may be too low": misleading.
var ErrNoCaps = errors.New("no CAP_BPF (or CAP_SYS_ADMIN): the service may not use eBPF")

// ErrMemlock: a map was refused with EPERM although shuntd has CAP_BPF and
// the memlock limit could not be lifted (kernels before 5.11 charge eBPF
// maps to RLIMIT_MEMLOCK; LimitMEMLOCK=infinity in the unit fixes it).
var ErrMemlock = errors.New("memlock limit too low for eBPF maps")
