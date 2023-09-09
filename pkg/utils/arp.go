package utils

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/mdlayher/arp"
)

func GetMac(ip net.IP, i string) (net.HardwareAddr, error) {
	iface, err := net.InterfaceByName(i)
	if err != nil {
		return nil, fmt.Errorf("<getMac>Could not find interface %s : %v\n", i, err)
	}

	client, err := arp.Dial(iface)
	if err != nil {
		return nil, fmt.Errorf("<getMac>Could not dial for interface %s : %v\n", i, err)
	}

	defer client.Close()
	addr := netip.AddrFrom16([16]byte(ip.To16()))
	mac, err := client.Resolve(addr)
	if err != nil {
		return nil, fmt.Errorf("<getMac>Could not resolve IP %s : %v\n", ip, err)
	}

	return mac, nil
}
