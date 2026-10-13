// Package cgroup manages the cgroup v2 subtree shuntd owns. Processes are
// placed into per-group cgroups; nftables matches sockets by cgroup.
//
// Linux only.
package cgroup
