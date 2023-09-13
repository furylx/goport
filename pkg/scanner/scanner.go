package scanner

import (
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
	// fmt.Printf("Target: %v\nPorts: %v\nMode: %v\nInterface: %v\n", t, p, m, iface)

	locIP, locMAC, tarMAC := collector(iface, t)

	// creating channel to close the listener
	stopCh := make(chan bool)

	// creating channels and buffer for the processing of the results
	pLen := float32(len(p))
	buffer := int((pLen * 0.03))
	openCh := make(chan string, buffer)
	closeCh := make(chan string, buffer*10)
	doneCh := make(chan bool)

	// openhandle
	handle, err := pcap.OpenLive(iface, snaplen, false, 1*time.Second)
	if err != nil {
		log.Fatalf("<Scan> error creating handle: %v", err)
	}
	defer handle.Close()

	switch m {
	case "stealth":
		// start listener (pass mode into listener) in goroutine
		listener = &StealthListener{}
		wg.Add(1)
		go listener.Start(iface, m, handle, stopCh, t, openCh, closeCh, doneCh)
		// loop over ports and send packets via handle
		InitiateStealthScan(t, p, handle, locIP, locMAC, tarMAC)
		wg.Wait()
	case "speed":
		// start listener (pass mode into listener) in goroutine
		// loop over ports and send packets via handle

	case "accuracy":
		// start listener (pass mode into listener) in goroutine
		// loop over ports and send packets via handle

	}

	// stop listener
	// fmt.Println("calling stop")
	// listener.Stop(stopCh)

}

// ScanListener serves as interface to end all the different listeners depending on the mode
type ScanListener interface {
	Start(i string, m string, h *pcap.Handle, c chan bool, t net.IP, co chan string, cc chan string, cd chan bool)
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
