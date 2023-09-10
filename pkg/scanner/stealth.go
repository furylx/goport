package scanner

import (
	"fmt"
	"log"
	"math/rand"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type StealthListener struct {
	iface string
	mode  string
}

type PortInfo struct {
	port    int
	status  string
	service string
}

var scannedPorts []PortInfo

func (s *StealthListener) Start(i string, m string, h *pcap.Handle, c chan bool, t net.IP) {
	defer wg.Done()
	packetSource := gopacket.NewPacketSource(h, h.LinkType())
	for {
		select {
		case packet := <-packetSource.Packets():
			if packet.Layer(layers.LayerTypeIPv4) != nil && packet.Layer(layers.LayerTypeTCP) != nil {
				handleResponse(packet, m, t)
			}

		case <-c:
			return
		}
	}
}

func (s *StealthListener) Stop(c chan bool) {
	fmt.Println("Killing listener")
	c <- false
}

func InitiateStealthScan(t net.IP, p []int, h *pcap.Handle, locIP net.IP, locMAC net.HardwareAddr, tarMAC net.HardwareAddr) {
	fmt.Println("Initiating stealth scan...")
	for _, port := range p {
		packet := craftSynPacket(t, port, locMAC, tarMAC, locIP)
		err := h.WritePacketData(packet)
		if err != nil {
			log.Fatalf("<InitiateStealthScan> error sending out packet: %v\n", err)
		}
		packet2 := craftSynPacket(t, port, locMAC, tarMAC, locIP)
		err = h.WritePacketData(packet2)
		if err != nil {
			log.Fatalf("<InitiateStealthScan> error sending out packet: %v\n", err)
		}
	}
}

func craftSynPacket(t net.IP, p int, locMac net.HardwareAddr, tarMac net.HardwareAddr, locIP net.IP) []byte {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
	}
	eth := layers.Ethernet{
		SrcMAC:       locMac,
		DstMAC:       tarMac,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Flags:    layers.IPv4DontFragment,
		Id:       uint16(rand.Uint32()),
		DstIP:    t,
		SrcIP:    locIP,
		Protocol: layers.IPProtocolTCP,
		Length:   40,
	}
	tcp := layers.TCP{
		Window:     64240,
		DstPort:    layers.TCPPort(p),
		SrcPort:    layers.TCPPort(20000 + rand.Intn(45535)),
		SYN:        true,
		Seq:        0, //uint32(rand.Int31()),
		DataOffset: 5,
	}
	tcp.SetNetworkLayerForChecksum(&ip)
	gopacket.SerializeLayers(buf, opts, &eth, &ip, &tcp)
	packetData := buf.Bytes()

	return packetData
}

func handleResponse(p gopacket.Packet, m string, t net.IP) map[int]string {
	// out := make(map[int]string)
	switch m {
	case "stealth":
		ipv4Layer := p.Layer(layers.LayerTypeIPv4)
		if ipv4Layer != nil {
			ipv4, _ := ipv4Layer.(*layers.IPv4) // Type assertion to get the actual IPv4 layer type
			if ipv4.SrcIP.Equal(t) {
				// fmt.Printf("<handleResponse> SrcIP: %v\tDstIP: %v\n", ipv4.SrcIP, ipv4.DstIP)

				tcpLayer := p.Layer(layers.LayerTypeTCP)
				if tcpLayer != nil {
					tcp, _ := tcpLayer.(*layers.TCP)
					if tcp.SYN && tcp.ACK {
						fmt.Printf("<handleResponse : %v>\n", tcp.SrcPort)
					}
				}
			}
		}
	}
	return nil
}
