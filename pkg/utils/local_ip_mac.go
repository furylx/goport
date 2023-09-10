package utils

import (
	"fmt"
	"log"
	"net"
)

func GetLocalIp(i string) (net.IP, error) {
	localIface, err := net.InterfaceByName(i)
	localIp, err := localIface.Addrs()
	if err != nil {
		log.Fatalf("<getLocalIp> Could not retrieve ip address of the specified interface: %v\t error: %v\n", i, err)
	}
	for _, i := range localIp {
		ip, _, err := net.ParseCIDR(i.String())
		if err != nil {
			log.Fatalf("<GetLocalIP> error parsing addresses: %v", err)
		} else if ip.To4() != nil {
			return ip.To4(), nil
		}
	}
	return nil, fmt.Errorf("<GetLocalIp>Could not determine local ip address")
}

func GetLocalMAC(i string) net.HardwareAddr {
	intf, err := net.InterfaceByName(i)
	if err != nil {
		log.Fatalf("<GetLocalMAC>Could not process interface: %v\n", err)
	}
	return intf.HardwareAddr
}
