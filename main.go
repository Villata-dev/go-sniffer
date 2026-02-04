
package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	// List network interfaces
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	// Flag for selecting the interface
	list := flag.Bool("list", false, "List all available network interfaces")
	device := flag.String("device", "", "Network interface to capture packets from")
	flag.Parse()

	if *list || (*device == "" && len(os.Args) == 1) {
		fmt.Println("Available network interfaces:")
		for _, d := range devices {
			fmt.Printf("Name: %s\n", d.Name)
			fmt.Printf("Description: %s\n", d.Description)
			fmt.Println("-----------")
		}
		if *device == "" {
			return
		}
	}

	if *device == "" {
		log.Fatal("Please specify the network interface to capture packets from with the -device flag")
	}

	// Open device
	handle, err := pcap.OpenLive(*device, 1024, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Error opening device %s: %v. Try running with sudo.", *device, err)
	}
	defer handle.Close()

	// Use a PacketSource to process packets
	fmt.Printf("Capturing packets on device %s...\n", *device)

	for {
		data, _, err := handle.ReadPacketData()
		if err != nil {
			log.Printf("Error reading packet: %v", err)
			continue
		}

		// Use NewPacket to process raw data
		packet := gopacket.NewPacket(data, handle.LinkType(), gopacket.Default)

		// Extract IPv4 layer
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer == nil {
			continue
		}
		ip, _ := ipLayer.(*layers.IPv4)

		// Extract transport layer (TCP or UDP)
		var protocol string
		var srcPort, dstPort string

		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			protocol = "TCP"
			srcPort = fmt.Sprintf("%d", tcp.SrcPort)
			dstPort = fmt.Sprintf("%d", tcp.DstPort)
		} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)
			protocol = "UDP"
			srcPort = fmt.Sprintf("%d", udp.SrcPort)
			dstPort = fmt.Sprintf("%d", udp.DstPort)
		}

		// Display packet information
		if protocol != "" {
			fmt.Printf("[%s] %s:%s -> %s:%s (len: %d)\n",
				protocol, ip.SrcIP, srcPort, ip.DstIP, dstPort, len(data))
		} else {
			// Handle IPv4 packets without TCP/UDP (e.g., ICMP)
			fmt.Printf("[IPv4] %s -> %s (len: %d)\n",
				ip.SrcIP, ip.DstIP, len(data))
		}
	}
}
