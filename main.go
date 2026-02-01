
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/google/gopacket"
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
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	fmt.Printf("Capturing packets on device %s...\n", *device)
	for packet := range packetSource.Packets() {
		// Process packets here
		fmt.Printf("Paquete capturado: [%s] Longitud: [%d] bytes\n", packet.Metadata().Timestamp.Format(time.RFC3339Nano), len(packet.Data()))
	}
}
