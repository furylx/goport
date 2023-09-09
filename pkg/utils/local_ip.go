package utils

import (
	"fmt"
	"log"
	"net"
)

func GetLocalIp(i string) []net.Addr {
	localIface, err := net.InterfaceByName(i)
	fmt.Println("localiface: ", localIface)
	localIp, err := localIface.Addrs()
	if err != nil {
		log.Fatalf("<getLocalIp> Could not retrieve ip address of the specified interface: %v\t error: %v\n", i, err)
	}
	fmt.Println("<getLocalIp>: ", localIp)
	return localIp
}
