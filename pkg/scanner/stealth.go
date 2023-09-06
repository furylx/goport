package scanner

import (
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	snaplen int32 = 1600
)

func InitiateStealthScan(t net.IP, p []int) {

}

func craftSynPacket(t net.IP, p int) []byte {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	gopacket.SerializeLayers(buf, opts,
		&layers.Ethernet{},
		&layers.IPv4{
			DstIP: t,
		},
		&layers.TCP{
			DstPort: layers.TCPPort(p),
			SYN:     true,
		})
	packetData := buf.Bytes()
	return packetData
}

func sendPacket(t net.IP, p []byte, iface string) error {
	handle, err := pcap.OpenLive(iface, snaplen, false, time.Second*10)
	if err != nil {
		return fmt.Errorf("<sendPacket> error creating handle: %v", err)
	}
	defer handle.Close()
	err = handle.WritePacketData(p)
	if err != nil {
		return fmt.Errorf("<sendPacket> error writing packet data: %v", err)
	}
	return nil
}

func listenForResponse(t net.IP, p int) {

}

func handleResponse(r string) {

}
