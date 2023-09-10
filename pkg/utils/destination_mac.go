package utils

import (
	"fmt"
	"log"
	"net"

	"github.com/jackpal/gateway"
)

func DstMAC(i string, t net.IP, locIP net.IP, locMAC net.HardwareAddr) net.HardwareAddr {
	if !IpClass(t) {
		gateway, err := gateway.DiscoverGateway()
		if err != nil {
			log.Fatalf("<dstMAC>Could not get local gateway IP\t%v", err)
		}
		fmt.Printf("gateway ip: >%v<\n", gateway)
		destMAC, err := GetMac(gateway, i, locIP, locMAC)
		if err != nil {
			log.Fatalf("<dstMAC>Could not get gateway MAC \t%v", err)
		}
		return destMAC
	} else {
		destMAC, err := GetMac(t, i, locIP, locMAC)
		if err != nil {
			log.Fatalf("<dstMAC>Could not get dstMAC: %v", err)
		}
		return destMAC
	}
}
