
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"unicode"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
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
	filter := flag.String("filter", "", "BPF filter for packet capture")
	output := flag.String("output", "", "Path to the output .pcap file")
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
	handle, err := pcap.OpenLive(*device, 65536, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Error opening device %s: %v. Try running with sudo.", *device, err)
	}
	defer handle.Close()

	// Initialize PCAP writer if -output is provided
	var pcapWriter *pcapgo.Writer
	if *output != "" {
		f, err := os.Create(*output)
		if err != nil {
			log.Fatalf("Error creating output file %s: %v", *output, err)
		}
		defer f.Close()

		pcapWriter = pcapgo.NewWriter(f)
		if err := pcapWriter.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
			log.Fatalf("Error writing PCAP header: %v", err)
		}
		fmt.Printf("Saving packets to: %s\n", *output)
	}

	// Apply BPF filter if provided
	if *filter != "" {
		err = handle.SetBPFFilter(*filter)
		if err != nil {
			log.Fatalf("Error applying BPF filter '%s': %v", *filter, err)
		}
	}

	// Setup signal handling for clean shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\nInterrupción detectada. Cerrando captura...")
		handle.Close()
	}()

	// Use a PacketSource to process packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	if *filter != "" {
		fmt.Printf("Escuchando en %s con filtro: %s...\n", *device, *filter)
	} else {
		fmt.Printf("Capturing packets on device %s...\n", *device)
	}
	for packet := range packetSource.Packets() {
		// Save packet if pcapWriter is active
		if pcapWriter != nil {
			err := pcapWriter.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
			if err != nil {
				log.Printf("Error writing packet to file: %v", err)
			}
		}

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
				protocol, ip.SrcIP, srcPort, ip.DstIP, dstPort, len(packet.Data()))
			inspectPayload(packet)
		} else {
			// Handle IPv4 packets without TCP/UDP (e.g., ICMP)
			fmt.Printf("[IPv4] %s -> %s (len: %d)\n",
				ip.SrcIP, ip.DstIP, len(packet.Data()))
		}
	}
}

func inspectPayload(packet gopacket.Packet) {
	appLayer := packet.ApplicationLayer()
	if appLayer == nil {
		return
	}

	payload := appLayer.Payload()
	if len(payload) == 0 {
		return
	}

	// Filter printable ASCII and truncate to 200 characters
	var sb strings.Builder
	for i, b := range payload {
		if i >= 200 {
			break
		}
		if unicode.IsPrint(rune(b)) || b == '\n' || b == '\r' || b == '\t' {
			sb.WriteByte(b)
		} else {
			sb.WriteByte('.')
		}
	}
	cleanPayload := sb.String()

	// Detect HTTP patterns
	httpPatterns := []string{"GET ", "POST ", "HTTP/1.1", "Authorization:", "Cookie:", "User-Agent:"}
	isHTTP := false
	for _, pattern := range httpPatterns {
		if strings.Contains(cleanPayload, pattern) {
			isHTTP = true
			break
		}
	}

	if isHTTP {
		fmt.Println("\n*** HTTP TRAFFIC DETECTED ***")
		fmt.Println(cleanPayload)
		fmt.Println("*****************************")
	}

	// Detect sensitive keywords
	sensitiveKeywords := []string{"user", "pass", "login", "password"}
	for _, keyword := range sensitiveKeywords {
		if strings.Contains(strings.ToLower(cleanPayload), keyword) {
			fmt.Println("\033[31m[!] ALERTA ROJA: SENSITIVE DATA DETECTED [!]\033[0m")
			break
		}
	}
}
