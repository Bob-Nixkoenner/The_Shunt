// Package routing maintains Shunt's policy routing: one table per tunnel and
// an ip rule per tunnel mark.
//
// Every tunnel table permanently holds an "unreachable default" route with a
// high metric. When the tunnel interface is gone its routes vanish with it,
// the unreachable route stays, and marked traffic gets ENETUNREACH instead of
// falling through to the main table. The kill switch is a property of the
// table, not of a running daemon.
//
// Linux only.
package routing
