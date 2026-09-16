package proxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

func TestNewDialer(t *testing.T) {
	cases := []struct {
		input       string
		wantScheme  string
		wantHost    string
		wantUser    string
		wantPass    string
		expectError bool
	}{
		{"127.0.0.1:1080", "socks5", "127.0.0.1:1080", "", "", false},
		{"socks5://127.0.0.1:1080", "socks5", "127.0.0.1:1080", "", "", false},
		{"socks://user:pass@127.0.0.1:1080", "socks5", "127.0.0.1:1080", "user", "pass", false},
		{"http://proxy.local:8080", "http", "proxy.local:8080", "", "", false},
		{"https://user:secret@proxy.local:8443", "https", "proxy.local:8443", "user", "secret", false},
		{"ftp://1.2.3.4:21", "", "", "", "", true},
		{"", "", "", "", "", true},
	}

	for _, tc := range cases {
		d, err := NewDialer(tc.input)
		if tc.expectError {
			if err == nil {
				t.Errorf("NewDialer(%q) expected error, got nil", tc.input)
			}
			continue
		}
		if err != nil {
			t.Fatalf("NewDialer(%q) unexpected error: %v", tc.input, err)
		}
		if d.scheme != tc.wantScheme {
			t.Errorf("scheme mismatch for %q: got %s, want %s", tc.input, d.scheme, tc.wantScheme)
		}
		if d.host != tc.wantHost {
			t.Errorf("host mismatch for %q: got %s, want %s", tc.input, d.host, tc.wantHost)
		}
		if d.user != tc.wantUser {
			t.Errorf("user mismatch for %q: got %s, want %s", tc.input, d.user, tc.wantUser)
		}
		if d.pass != tc.wantPass {
			t.Errorf("pass mismatch for %q: got %s, want %s", tc.input, d.pass, tc.wantPass)
		}
	}
}

// startMockHttpProxy creates a mock HTTP proxy that supports CONNECT
func startMockHttpProxy(t *testing.T, expectedAuth string) (string, func()) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen mock proxy: %v", err)
	}

	done := make(chan struct{})

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-done:
					return
				default:
					return
				}
			}

			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)

				reqLine, err := br.ReadString('\n')
				if err != nil {
					return
				}

				parts := strings.Split(strings.TrimSpace(reqLine), " ")
				if len(parts) < 2 || parts[0] != "CONNECT" {
					c.Write([]byte("HTTP/1.1 405 Method Not Allowed\r\n\r\n"))
					return
				}
				targetAddr := parts[1]

				var authHeader string
				for {
					line, err := br.ReadString('\n')
					if err != nil || line == "\r\n" || line == "\n" {
						break
					}
					if strings.HasPrefix(strings.ToLower(line), "proxy-authorization:") {
						authHeader = strings.TrimSpace(line[len("proxy-authorization:"):])
					}
				}

				if expectedAuth != "" {
					expectedHeader := "Basic " + base64.StdEncoding.EncodeToString([]byte(expectedAuth))
					if authHeader != expectedHeader {
						c.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"))
						return
					}
				}

				// Dial target
				targetConn, err := net.Dial("tcp", targetAddr)
				if err != nil {
					c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
					return
				}
				defer targetConn.Close()

				c.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))

				// Tunnel
				go io.Copy(targetConn, br)
				io.Copy(c, targetConn)
			}(conn)
		}
	}()

	cleanup := func() {
		close(done)
		ln.Close()
	}

	return ln.Addr().String(), cleanup
}

func TestHttpConnectTunnel(t *testing.T) {
	// 1. Start echo server (target)
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo server: %v", err)
	}
	defer echoLn.Close()

	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				io.Copy(conn, conn)
			}(c)
		}
	}()

	// 2. Start mock HTTP proxy with auth
	proxyAddr, stopProxy := startMockHttpProxy(t, "alice:secret123")
	defer stopProxy()

	// 3. Setup dialer
	proxyURL := fmt.Sprintf("http://alice:secret123@%s", proxyAddr)
	d, err := NewDialer(proxyURL)
	if err != nil {
		t.Fatalf("NewDialer: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	conn, err := d.DialContext(ctx, "tcp", echoLn.Addr().String())
	if err != nil {
		t.Fatalf("DialContext via HTTP proxy failed: %v", err)
	}
	defer conn.Close()

	// 4. Test write / read
	msg := "Hello through proxy!\n"
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatalf("Write: %v", err)
	}

	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("Read: %v", err)
	}

	if string(buf) != msg {
		t.Fatalf("Got %q, want %q", string(buf), msg)
	}
}

func TestManagerPoolAndRotation(t *testing.T) {
	// Create temp proxy file
	content := "http://1.1.1.1:8080\nsocks5://2.2.2.2:1080\n# comment\nhttp://3.3.3.3:3128\n"
	tmpFile, err := os.CreateTemp("", "proxies-*.txt")
	if err != nil {
		t.Fatalf("create temp: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("write temp: %v", err)
	}
	tmpFile.Close()

	n, err := LoadFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if n != 3 {
		t.Fatalf("expected 3 proxies loaded, got %d", n)
	}

	SetEnabled(true)
	if !IsEnabled() {
		t.Fatalf("expected IsEnabled() = true")
	}

	st := Status()
	if !strings.Contains(st, "3 шт.") {
		t.Fatalf("unexpected status: %s", st)
	}

	// Verify rotation picks all three in sequence
	p1 := pickDialer()
	p2 := pickDialer()
	p3 := pickDialer()
	p4 := pickDialer()

	if p1 == nil || p2 == nil || p3 == nil || p4 == nil {
		t.Fatalf("pickDialer returned nil")
	}

	hosts := []string{p1.host, p2.host, p3.host}
	if hosts[0] == hosts[1] || hosts[1] == hosts[2] {
		t.Errorf("expected round-robin variation, got %v", hosts)
	}
	if p4.host != p1.host {
		t.Errorf("expected p4 (%s) to match p1 (%s) after round-robin cycle", p4.host, p1.host)
	}

	// Reset
	SetEnabled(false)
	LoadFile("")
	SetSingle("")
	if IsEnabled() {
		t.Fatalf("expected IsEnabled() = false after reset")
	}
}
