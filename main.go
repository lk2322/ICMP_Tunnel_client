package main

import (
	"errors"
	"fmt"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"
	"net"
	"os"
)

var REMOTE = "95.217.146.251"

// CalculateIPv4Checksum calculate checksum for ip package
func CalculateIPv4Checksum(bytes []byte) uint16 {
	// Clear checksum bytes
	bytes[10] = 0
	bytes[11] = 0

	// Compute checksum
	var csum uint32
	for i := 0; i < len(bytes); i += 2 {
		csum += uint32(bytes[i]) << 8
		csum += uint32(bytes[i+1])
	}

	for csum > 0xFFFF {
		csum = (csum >> 16) + uint32(uint16(csum))
	}
	return ^uint16(csum)
}

// Read outcoming packets (from user) and send to remote
func Read(session wintun.Session) (int, error) {
	buf := make([]byte, 65555)
	for {
		packet, err := session.ReceivePacket()
		switch err {
		case nil:
			header, _ := ipv4.ParseHeader(packet)
			copy(buf[:header.TotalLen], packet)
			session.ReleaseReceivePacket(packet)
			fmt.Println(header)
			if header.Protocol == 6 {
				m := icmp.Message{
					Type: ipv4.ICMPTypeEcho, Code: 255,
					Body: &icmp.Echo{
						ID: os.Getpid() & 0xffff, Seq: 1, //<< uint(seq), // TODO
						Data: buf[header.Len:header.TotalLen],
					},
				}
				b, _ := m.Marshal(nil)
				conn, err := net.DialIP("ip4:icmp", nil, &net.IPAddr{IP: net.IPv4(95, 217, 146, 251)})
				if err != nil {
					fmt.Printf("Dial failed: %v \n", err)
				}
				_, err = conn.Write(b)
				if err != nil {
					fmt.Printf("Send failed: %v \n", err)
				}
			}

		case windows.ERROR_NO_MORE_ITEMS:
			continue
		case windows.ERROR_HANDLE_EOF:
			return 0, os.ErrClosed
		case windows.ERROR_INVALID_DATA:
			return 0, errors.New("Send ring corrupt")
		}
	}
}

func Write(session wintun.Session) (int, error) {

	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")

	if err != nil {
		fmt.Printf("Listen ICMP failed: %v \n", err)
	}
	buf := make([]byte, 65555)
	for {
		if err != nil {
			return 0, err
		}
		n, addr, err := conn.ReadFrom(buf)
		fmt.Println(string(buf[:n]))
		if err != nil {
			fmt.Printf("Read failed: %v \n", err)
		}
		packet, err := session.AllocateSendPacket(1500)
		if err != nil {
			fmt.Printf("Allocate failed: %v \n", err)
		}

		header := &ipv4.Header{
			Version:  4,
			TOS:      0,
			Len:      20,
			TotalLen: len(buf[:n]) + 20,
			TTL:      64,
			Protocol: 6,
			Src:      addr.(*net.IPAddr).IP,
			Dst:      net.IPv4(0, 0, 0, 0),
		}
		header.Checksum = int(CalculateIPv4Checksum(packet))
		b, err := header.Marshal()
		if err != nil {
			fmt.Printf("Marshal failed: %v \n", err)
		}
		res := append(b, buf[:n]...)
		session.SendPacket(res)

	}

}

func main() {
	adapter, _ := wintun.CreateAdapter("MyAdapter", "wintun", nil)
	session, _ := adapter.StartSession(0x800000)
	go func() {
		_, err := Read(session)
		if err != nil {
			fmt.Println(err)
		}
	}()
	_, err := Write(session)

	if err != nil {
		fmt.Println(err)
	}

	adapter.Close()

}
