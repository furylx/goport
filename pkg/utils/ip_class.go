package utils

import (
	"net"
	"net/netip"
)

func IpClass(ip net.IP) bool {
	addr := netip.AddrFrom4([4]byte(ip.To4()))
	return addr.IsPrivate()
}
