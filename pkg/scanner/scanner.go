package scanner

import (
	"fmt"
	"net"
)

func Scan(t net.IP, p []int, m string, iface string) {
	fmt.Printf("Target: %v\nPorts: %v\nMode: %v\nInterface: %v\n", t, p, m, iface)

	// openhandle
	// defer handle.close

	// start listener (pass mode into listener) in goroutine
	// loop over ports and send packets via handle

	// sleep to wait for responses

	// stop listener
}
