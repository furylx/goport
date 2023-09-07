package scanner

import (
	"fmt"
	"log"
	"math/rand"
	"net"
	"time"

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

func (s *StealthListener) Start(i string, m string, h *pcap.Handle, c chan bool, t net.IP) {
	defer wg.Done()
	packetSource := gopacket.NewPacketSource(h, h.LinkType())
	fmt.Println("Stealth listener starting...", packetSource.Packets())
	time.Sleep(time.Second * 5)
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

func InitiateStealthScan(t net.IP, p []int, h *pcap.Handle) {
	fmt.Println("Initiating stealth scan...")
	for _, port := range p {
		packet := craftSynPacket(t, port)
		fmt.Println("THE PACKET: ", packet)
		testing(packet)
		// err := h.WritePacketData(packet)
		// fmt.Println("Packets out!! ", err)
		// if err != nil {
		// 	log.Fatalf("<InitiateStealthScan> error sending out packet: %v\n", err)
		// }
	}
}

func craftSynPacket(t net.IP, p int) []byte {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	gopacket.SerializeLayers(buf, opts,
		&layers.IPv4{
			DstIP:    t,
			SrcIP:    net.IPv4(10, 1, 1, 27),
			Protocol: layers.IPProtocolTCP,
		},
		&layers.TCP{
			DstPort: layers.TCPPort(p),
			SrcPort: layers.TCPPort(35000),
			SYN:     true,
			Seq:     uint32(rand.Int31()),
		})
	packetData := buf.Bytes()
	fmt.Println("Crafting packet: ", packetData)
	return packetData
}

// func sendPacket(t net.IP, p []byte, iface string) error {}

func handleResponse(p gopacket.Packet, m string, t net.IP) map[int]string {
	// out := make(map[int]string)
	switch m {
	case "stealth":
		ipv4Layer := p.Layer(layers.LayerTypeIPv4)
		if ipv4Layer != nil {
			ipv4, _ := ipv4Layer.(*layers.IPv4) // Type assertion to get the actual IPv4 layer type
			if ipv4.DstIP.Equal(t) {
				fmt.Printf("<handleResponse ipv4: %v\t%v\t%v>\n", ipv4.SrcIP, ipv4.DstIP, t)
			}
			fmt.Printf("%v\t%v\n", ipv4.DstIP, ipv4.SrcIP)
		}
		// tcpLayer := p.Layer(layers.LayerTypeTCP)
		// if tcpLayer != nil {
		// 	tcp, _ := tcpLayer.(*layers.TCP)
		// 	fmt.Printf("<handleResponse : %v>\n", tcp)
		// }
		// check for response according to stealth scan
	}

	return nil
}

func testing(p []byte) {
	conn, err := net.Dial("ip4:tcp", "10.1.1.35")
	if err != nil {
		log.Fatal(err)
	}
	_, err = conn.Write(p)
	if err != nil {
		log.Fatal(err)
	}

}
