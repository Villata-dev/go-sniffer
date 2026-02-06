
package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/google/gopacket"
)

func TestInspectPayload(t *testing.T) {
	tests := []struct {
		name     string
		payload  string
		wantHTTP bool
		wantRed  bool
	}{
		{
			name:     "HTTP GET with password",
			payload:  "GET / HTTP/1.1\r\nHost: localhost\r\n\r\nuser=admin&password=123",
			wantHTTP: true,
			wantRed:  true,
		},
		{
			name:     "Non-HTTP traffic with sensitive word",
			payload:  "This is a secret login attempt",
			wantHTTP: false,
			wantRed:  true,
		},
		{
			name:     "Normal traffic",
			payload:  "Just some random data",
			wantHTTP: false,
			wantRed:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Capture stdout
			oldStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			// Create a mock packet.
			// We use a simple way to create a packet that has an application layer.
			// By decoding as LayerTypePayload, gopacket will treat the whole data as the payload.
			packet := gopacket.NewPacket([]byte(tt.payload), gopacket.LayerTypePayload, gopacket.Default)

			inspectPayload(packet)

			// Restore stdout
			w.Close()
			os.Stdout = oldStdout
			var buf bytes.Buffer
			_, _ = io.Copy(&buf, r)
			got := buf.String()

			if tt.wantHTTP && !strings.Contains(got, "HTTP TRAFFIC DETECTED") {
				t.Errorf("test '%s': expected HTTP detection, but got: %s", tt.name, got)
			}
			if tt.wantRed && !strings.Contains(got, "ALERTA ROJA") {
				t.Errorf("test '%s': expected ALERTA ROJA, but got: %s", tt.name, got)
			}
			if !tt.wantHTTP && strings.Contains(got, "HTTP TRAFFIC DETECTED") {
				t.Errorf("test '%s': did not expect HTTP detection, but got: %s", tt.name, got)
			}
			if !tt.wantRed && strings.Contains(got, "ALERTA ROJA") {
				t.Errorf("test '%s': did not expect ALERTA ROJA, but got: %s", tt.name, got)
			}
		})
	}
}
