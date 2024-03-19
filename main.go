package main

import (
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"io"
	"log"
	"net"
)

func main() {
	// Start TCP server
	tcpListener, err := net.Listen("tcp", "localhost:8777")
	if err != nil {
		log.Fatal(err)
	}
	defer tcpListener.Close()

	// Start ICMP listener
	icmpConn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		log.Fatal(err)
	}
	defer icmpConn.Close()

	for {
		// Accept incoming connections
		conn, err := tcpListener.Accept()
		if err != nil {
			log.Fatal(err)
		}

		go handleConnection(conn, icmpConn)
	}
}

func handleConnection(conn net.Conn, icmpConn *icmp.PacketConn) {
	defer conn.Close()

	// Create buffer to read data from the connection
	buf := make([]byte, 4096)

	// Loop to handle multiple packets
	for {
		// Read data from the connection
		n, err := conn.Read(buf)
		if err != nil {
			if err == io.EOF {
				break // Connection closed, exit the loop
			}
			log.Fatal(err)
		}

		// Create ICMP message
		dst, err := net.ResolveIPAddr("ip4", "172.17.200.86")
		if err != nil {
			log.Fatal(err)
		}

		msg := icmp.Message{
			Type: ipv4.ICMPTypeEcho, Code: 255,
			Body: &icmp.Echo{
				ID: 0x1234, Seq: 1,
				Data: buf[:n],
			},
		}

		bytes, err := msg.Marshal(nil)
		if err != nil {
			log.Fatal(err)
		}

		// Send ICMP message
		if _, err := icmpConn.WriteTo(bytes, dst); err != nil {
			log.Fatal(err)
		}

		// Listen for ICMP echo reply
		buf2 := make([]byte, 4096)
		n, _, err = icmpConn.ReadFrom(buf2)
		if err != nil {
			log.Fatal(err)
		}

		msg_r, err := icmp.ParseMessage(ipv4.ICMPTypeEchoReply.Protocol(), buf2[:n])
		if err != nil {
			log.Fatal(err)
		}

		echo, ok := msg_r.Body.(*icmp.Echo)
		if !ok {
			log.Fatal("got wrong message body type in echo reply")
		}

		// Send the data as a TCP packet
		if _, err := conn.Write(echo.Data); err != nil {
			log.Fatal(err)
		}
	}
}
