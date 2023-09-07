package scanner

import (
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	snaplen int32 = 1600
)

type StealthListener struct {
	iface string
	mode  string
}

func (s *StealthListener) Start(i string, m string, h *pcap.Handle, c chan bool) {
	packetSource := gopacket.NewPacketSource(h, h.LinkType())
	for {
		select {
		case packet := <-packetSource.Packets():
			handleResponse(packet, m)
		case <-c:
			return
		}
	}
}

func (s *StealthListener) Stop(c chan bool) {
	c <- false
}

func InitiateStealthScan(t net.IP, p []int, h *pcap.Handle) {
	for _, port := range p {
		err := h.WritePacketData(craftSynPacket(t, port))
		if err != nil {
			log.Fatalf("<InitiateStealthScan> error sending out packet: %v\n", err)
		}
	}
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

// func sendPacket(t net.IP, p []byte, iface string) error {}

func handleResponse(p gopacket.Packet, m string) map[int]string {
	// out := make(map[int]string)
	switch m {
	case "stealth":
		ipv4Layer := p.Layer(layers.LayerTypeIPv4)
		if ipv4Layer != nil {
			ipv4, _ := ipv4Layer.(*layers.IPv4) // Type assertion to get the actual IPv4 layer type
		}
		tcpLayer := p.Layer(layers.LayerTypeTCP)
		if tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
		}
		// check for response according to stealth scan
	}

	return nil
}
