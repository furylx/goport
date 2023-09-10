package utils

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func GetMac(ip net.IP, i string, locIP net.IP, locMAC net.HardwareAddr) (net.HardwareAddr, error) {

	handle, err := pcap.OpenLive(i, 1600, true, (100 * time.Microsecond))
	if err != nil {
		log.Fatalf("Unable to open handle for ARP request: %v", err)
	}
	defer handle.Close()

	arpPacket := craftArpPacket(locMAC, ip.To4(), locIP.To4())

	handle.WritePacketData(arpPacket)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	timeout := time.After(10 * time.Second)

	for {
		select {
		case packet := <-packetSource.Packets():
			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer != nil {
				arpReply, _ := arpLayer.(*layers.ARP)
				if arpReply.Operation == layers.ARPReply && net.IP(arpReply.SourceProtAddress).Equal(ip) {
					handle.Close()
					return arpReply.SourceHwAddress, nil
				}
			}
		case <-timeout:
			handle.Close()
			return nil, fmt.Errorf("ARP request timed out")
		}

	}
}

func craftArpPacket(locM net.HardwareAddr, tarIP []byte, locIP []byte) []byte {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	eth := layers.Ethernet{
		SrcMAC:       locM,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceProtAddress: locIP,
		DstProtAddress:    tarIP,
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		SourceHwAddress:   locM,
	}
	gopacket.SerializeLayers(buf, opts, &eth, &arp)
	packetData := buf.Bytes()

	return packetData
}
