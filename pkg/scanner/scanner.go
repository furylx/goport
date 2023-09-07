package scanner

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/google/gopacket/pcap"
)

var (
	listener ScanListener
)

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
	// err = handle.WritePacketData(p)
	// if err != nil {
	// 	return fmt.Errorf("<sendPacket> error writing packet data: %v", err)
	// }

	switch m {
	case "stealth":
		// start listener (pass mode into listener) in goroutine
		listener = &StealthListener{
			iface: iface,
			mode:  m,
		}
		go listener.Start(m, iface, handle, stopCh)
		// loop over ports and send packets via handle
		InitiateStealthScan(t, p, handle)

	case "speed":
		// start listener (pass mode into listener) in goroutine
		// loop over ports and send packets via handle

	case "accuracy":
		// start listener (pass mode into listener) in goroutine
		// loop over ports and send packets via handle

	}

	time.Sleep(10)

	// stop listener
	listener.Stop(stopCh)
}

// ScanListener serves as interface to end all the different listeners depending on the mode
type ScanListener interface {
	Start(i string, m string, h *pcap.Handle, c chan bool)
	Stop(c chan bool)
}
