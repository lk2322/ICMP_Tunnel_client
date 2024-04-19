package main

import "testing"

func TestCalculateIPv4Checksum(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected uint16
	}{
		{
			name:     "Test case 1",
			input:    []byte{0x45, 0x00, 0x00, 0x54, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0xAC, 0x10, 0x00, 0x02, 0xAC, 0x10, 0x00, 0x01},
			expected: 0xE280,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := CalculateIPv4Checksum(test.input)
			if result != test.expected {
				t.Errorf("Test case %s failed: expected %04X, got %04X", test.name, test.expected, result)
			}
		})
	}
}
