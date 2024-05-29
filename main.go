package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// sendRequest sends an ICMP Echo request with the given data and returns the response.
func sendRequest(data []byte, remoteIP *string) (*icmp.Message, error) {
	addr := &net.IPAddr{IP: net.ParseIP(*remoteIP)}
	conn, err := net.DialIP("ip4:icmp", nil, addr)
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 255,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  1,
			Data: data,
		},
	}
	b, err := msg.Marshal(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ICMP message: %w", err)
	}

	if _, err := conn.Write(b); err != nil {
		return nil, fmt.Errorf("failed to send ICMP request: %w", err)
	}

	buf := make([]byte, 65535)
	_, _, err = conn.ReadFrom(buf)
	if err != nil {
		return nil, fmt.Errorf("failed to read ICMP response: %w", err)
	}

	msg_res, err := icmp.ParseMessage(ipv4.ICMPTypeEcho.Protocol(), buf)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ICMP message: %w", err)
	}

	return msg_res, nil
}

// handleTunneling handles HTTP CONNECT requests by establishing a tunnel
// between the client and the target server.
func handleTunneling(w http.ResponseWriter, r *http.Request) {
	destConn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer destConn.Close()

	w.WriteHeader(http.StatusOK)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer clientConn.Close()

	go transfer(destConn, clientConn)
	transfer(clientConn, destConn)
}

// handleHTTP handles regular HTTP requests by forwarding them over ICMP.
func handleHTTP(w http.ResponseWriter, req *http.Request, remoteIP *string) {
	var buf bytes.Buffer
	if err := req.WriteProxy(&buf); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	msg, err := sendRequest(buf.Bytes(), remoteIP)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	fmt.Printf("Get ICMP packet Type: %v Code: %v \n", int(msg.Type.(ipv4.ICMPType)), msg.Code)

	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(msg.Body.(*icmp.Echo).Data)), req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, err = io.Copy(w, resp.Body)
	log.Println(resp)
	if err != nil {
		log.Println(err)
	}
}

// transfer copies data between two connections.
func transfer(dst io.WriteCloser, src io.ReadCloser) {
	defer dst.Close()
	defer src.Close()
	io.Copy(dst, src)
}

// copyHeader copies HTTP headers from one header map to another.
func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func main() {

	remoteIP := flag.String("remote-ip", "", "Remote IP address to send ICMP requests to")
	localPort := flag.String("local-port", "8888", "Local port to listen on")
	flag.Parse()

	if *remoteIP == "" {
		fmt.Println("Error: -remote-ip flag is required")
		flag.Usage()
		os.Exit(1)
	}

	server := &http.Server{
		Addr: ":" + *localPort,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodConnect {
				handleTunneling(w, r)
			} else {
				handleHTTP(w, r, remoteIP)
			}
		}),
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}

	fmt.Printf("Proxy server listening on :%s, forwarding requests to %s via ICMP\n", *localPort, *remoteIP)
	log.Fatal(server.ListenAndServe())
}
