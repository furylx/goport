package utils

import (
	"fmt"
	"log"
	"net"
	"time"
)

func DetermineLocalGateway() (net.IP, error) {
	fmt.Println("Dialer starting")
	dialer, err := net.DialTimeout("udp", "1.1.1.1:80", (time.Second * 5))
	if err != nil {
		log.Fatalf("<Dialer> %v", err)
		return nil, err
	}
	addr := dialer.LocalAddr()
	fmt.Println("localAddr: ", addr)
	return nil, nil
}
