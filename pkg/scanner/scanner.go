package scanner

import (
	"fmt"
	"goport/pkg/utils"
	"log"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket/pcap"
)

const (
	snaplen int32 = 1600
)

var (
	listener ScanListener
	wg       sync.WaitGroup
)

// Scan creates the handle to send and receive the packets, initiates the right scan mode and closes the handle and the listener when done
func Scan(t net.IP, p []int, m string, iface string) {
	fmt.Printf("Target: %v\nPorts: %v\nMode: %v\nInterface: %v\n", t, p, m, iface)

	locMAC, locIP, tarMAC := collector(iface, t)

	// creating channel to close the listener
	stopCh := make(chan bool)
	// openhandle
	// defer handle.close
	handle, err := pcap.OpenLive(iface, snaplen, false, 1*time.Millisecond)
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
		InitiateStealthScan(t, p, handle, locMAC, tarMAC, locIP)
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

// collector gathers all necessary values to prevent querying stuff mutliple times (local ip, local mac, target mac which depends on the target ip class)
func collector(i string, t net.IP) (net.IP, net.HardwareAddr, net.HardwareAddr) {

	localIP, err := utils.GetLocalIp(i)
	if err != nil {
		log.Fatalf("<collector>%v", err)
	}
	localMAC := utils.GetLocalMAC(i)

	targetMAC := utils.DstMAC(i, t, localIP, localMAC)

	return localIP, localMAC, targetMAC
}
