package scanner

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket/pcap"
)

var (
	listener ScanListener
	wg       sync.WaitGroup
)

// func getLocalIp(i string) []net.Addr {
// 	localIface, err := net.InterfaceByName(i)
// 	localIp, err := localIface.Addrs()
// 	if err != nil {
// 		log.Fatalf("<getLocalIp> Could not retrieve ip address of the specified interface: %v\t error: %v\n", i, err)
// 	}
// 	fmt.Println("<getLocalIp>: ", localIp)
// 	return localIp
// }

// Scan creates the handle to send and receive the packets, initiates the right scan mode and closes the handle and the listener when done
func Scan(t net.IP, p []int, m string, iface string) {
	fmt.Printf("Target: %v\nPorts: %v\nMode: %v\nInterface: %v\n", t, p, m, iface)

	// creating channel to close the listener
	stopCh := make(chan bool)
	// openhandle
	// defer handle.close
	handle, err := pcap.OpenLive(iface, snaplen, false, time.Second*10)
	if err != nil {
		log.Fatalf("<Scan> error creating handle: %v", err)
	}
	defer handle.Close()

	switch m {
	case "stealth":
		// start listener (pass mode into listener) in goroutine
		listener = &StealthListener{
			iface: iface,
			mode:  m,
		}
		wg.Add(1)
		go listener.Start(iface, m, handle, stopCh, t)
		// loop over ports and send packets via handle
		InitiateStealthScan(t, p, handle)
		wg.Wait()
	case "speed":
		// start listener (pass mode into listener) in goroutine
		// loop over ports and send packets via handle

	case "accuracy":
		// start listener (pass mode into listener) in goroutine
		// loop over ports and send packets via handle

	}
	fmt.Println("#########sleeping 10#########")
	time.Sleep(time.Second * 10)

	// stop listener
	fmt.Println("calling stop")
	listener.Stop(stopCh)
}

// ScanListener serves as interface to end all the different listeners depending on the mode
type ScanListener interface {
	Start(i string, m string, h *pcap.Handle, c chan bool, t net.IP)
	Stop(c chan bool)
}
