package fwd

import (
	"testing"
)

func TestParseScanPortList(t *testing.T) {
	// Default
	ports, err := ParseScanPortList("")
	if err != nil || len(ports) != len(DefaultScanPorts) {
		t.Fatalf("empty input should return DefaultScanPorts, got %v err %v", ports, err)
	}

	// Custom list
	ports, err = ParseScanPortList("80,443,554")
	if err != nil || len(ports) != 3 || ports[0] != 80 || ports[1] != 443 || ports[2] != 554 {
		t.Fatalf("custom list failed: got %v err %v", ports, err)
	}

	// Range
	ports, err = ParseScanPortList("80-83")
	if err != nil || len(ports) != 4 || ports[0] != 80 || ports[3] != 83 {
		t.Fatalf("range list failed: got %v err %v", ports, err)
	}

	// With colon prefix (like 0:80,81)
	ports, err = ParseScanPortList("0:80,81")
	if err != nil || len(ports) != 2 || ports[0] != 80 || ports[1] != 81 {
		t.Fatalf("colon list failed: got %v err %v", ports, err)
	}
}
