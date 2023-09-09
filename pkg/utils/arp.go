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

func GetMac(ip net.IP, i string) (net.HardwareAddr, error) {
	handle, err := pcap.OpenLive(i, 1600, true, (10 * time.Second))
	if err != nil {
		log.Fatalf("Unable to open handle for ARP request: %v", err)
	}
	defer handle.Close()

	arpPacket := craftArpPacket()

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

func craftArpPacket() []byte {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	eth := layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x64, 0x4b, 0xf0, 0x38, 0x09, 0xa4},
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceProtAddress: []byte{10, 1, 1, 27},
		DstProtAddress:    []byte{10, 1, 1, 1},
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		SourceHwAddress:   net.HardwareAddr{0x64, 0x4b, 0xf0, 0x38, 0x09, 0xa4},
	}
	gopacket.SerializeLayers(buf, opts, &eth, &arp)
	packetData := buf.Bytes()

	return packetData
}
