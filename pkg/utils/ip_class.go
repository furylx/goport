package utils

import (
	"net"
	"net/netip"
)

func IpClass(ip net.IP) bool {
	addr := netip.AddrFrom16([16]byte(ip.To16()))
	return addr.IsPrivate()
}
