package scanner

import (
	"fmt"
	"net"
)

func Scan(t net.IP, p []int, m string) {
	fmt.Printf("Target: %v\nPorts: %v\nMode: %v\n", t, p, m)
}
