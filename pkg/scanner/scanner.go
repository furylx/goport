package scanner

import (
	"fmt"
	"goport/pkg/utils"
	"log"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket/pcap"
	"github.com/jackpal/gateway"
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
	fmt.Printf("############################\n%v\n", dstMAC(iface, t))
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

func dstMAC(i string, t net.IP) net.HardwareAddr {
	var gatewayMAC net.HardwareAddr = nil
	localip, err := utils.GetLocalIp(i)
	if err != nil {
		log.Fatalf("<dstMAC>Could not determine local IP")
	}
	if utils.IpClass(t) {
		fmt.Println("Private IP: ", t)
		gateway, err := gateway.DiscoverGateway()
		if err != nil {
			log.Fatalf("<dstMAC>Could not get local gateway IP\t%v", err)
		}
		fmt.Printf("gateway ip: >%v<\n", gateway)
		gatewayMAC, err = utils.GetMac(gateway, i)
		if err != nil {
			log.Fatalf("<dstMAC>Could not get gateway MAC \t%v", err)
		}
	} else {
		fmt.Println("Public IP: ", t)
		utils.GetMac(localip, i)
	}
	return gatewayMAC
}
