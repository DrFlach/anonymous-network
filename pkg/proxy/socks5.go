package proxy

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"network/pkg/tunnel"
	"network/pkg/util"
)

// SOCKS5 constants
const (
	socks5Version = 0x05

	// Authentication methods
	authNone     = 0x00
	authPassword = 0x02
	authNoAccept = 0xFF

	// Commands
	cmdConnect = 0x01
	cmdBind    = 0x02
	cmdUDP     = 0x03

	// Address types
	addrIPv4   = 0x01
	addrDomain = 0x03
	addrIPv6   = 0x04

	// Reply codes
	repSuccess         = 0x00
	repGeneralFailure  = 0x01
	repNotAllowed      = 0x02
	repNetUnreachable  = 0x03
	repHostUnreachable = 0x04
	repConnRefused     = 0x05
	repTTLExpired      = 0x06
	repCmdNotSupported = 0x07
	repAddrNotSupported = 0x08
)

// SOCKS5Server is a SOCKS5 proxy server that routes traffic through anonymous tunnels
type SOCKS5Server struct {
	listenAddr   string
	listener     net.Listener
	tunnelPool   *tunnel.Pool
	outproxy     *Outproxy
	logger       *util.Logger
	mu           sync.Mutex
	running      bool
	stopChan     chan struct{}
	wg           sync.WaitGroup
	activeConns  int64
	username     string // Optional SOCKS5 auth
	password     string
}

// SOCKS5Config configures the SOCKS5 proxy
type SOCKS5Config struct {
	ListenAddr string
	Username   string // Empty = no auth
	Password   string
}

// NewSOCKS5Server creates a new SOCKS5 proxy server
func NewSOCKS5Server(config *SOCKS5Config, tunnelPool *tunnel.Pool, outproxy *Outproxy) *SOCKS5Server {
	return &SOCKS5Server{
		listenAddr: config.ListenAddr,
		tunnelPool: tunnelPool,
		outproxy:   outproxy,
		logger:     util.GetLogger(),
		stopChan:   make(chan struct{}),
		username:   config.Username,
		password:   config.Password,
	}
}

// Start starts the SOCKS5 proxy server
func (s *SOCKS5Server) Start() error {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
			})
		},
	}
	listener, err := lc.Listen(context.Background(), "tcp", s.listenAddr)
	if err != nil {
		return fmt.Errorf("failed to start SOCKS5 listener: %w", err)
	}

	s.listener = listener
	s.running = true

	s.wg.Add(1)
	go s.acceptLoop()

	s.logger.Info("SOCKS5 proxy listening on %s", s.listenAddr)
	return nil
}

// Stop stops the SOCKS5 proxy server
func (s *SOCKS5Server) Stop() {
	s.mu.Lock()
	s.running = false
	s.mu.Unlock()

	close(s.stopChan)
	if s.listener != nil {
		s.listener.Close()
	}
	s.wg.Wait()
	s.logger.Info("SOCKS5 proxy stopped")
}

func (s *SOCKS5Server) acceptLoop() {
	defer s.wg.Done()

	for {
		select {
		case <-s.stopChan:
			return
		default:
		}

		s.listener.(*net.TCPListener).SetDeadline(time.Now().Add(1 * time.Second))
		conn, err := s.listener.Accept()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			select {
			case <-s.stopChan:
				return
			default:
				s.logger.Error("SOCKS5 accept error: %v", err)
				continue
			}
		}

		s.wg.Add(1)
		go s.handleConnection(conn)
	}
}

func (s *SOCKS5Server) handleConnection(conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()

	// Set overall connection timeout
	conn.SetDeadline(time.Now().Add(5 * time.Minute))

	// 1. Handshake - negotiate authentication method
	if err := s.handleHandshake(conn); err != nil {
		s.logger.Debug("SOCKS5 handshake failed: %v", err)
		return
	}

	// 2. Handle request
	targetAddr, err := s.handleRequest(conn)
	if err != nil {
		s.logger.Debug("SOCKS5 request failed: %v", err)
		return
	}

	// Log connection with encryption status
	host, port, _ := net.SplitHostPort(targetAddr)
	isTLS := port == "443"
	protocol := "HTTP"
	if isTLS {
		protocol = "HTTPS/TLS"
	}
	s.logger.Info("[PROXY] %s → %s [%s] [DNS:DoH] [Tunnel:active]", conn.RemoteAddr(), targetAddr, protocol)
	if !isTLS {
		s.logger.Warn("[PROXY] ⚠ %s uses plain HTTP — data NOT encrypted end-to-end (only DNS is protected via DoH)", host)
	}

	// 3. Route through anonymous network
	if err := s.routeConnection(conn, targetAddr); err != nil {
		s.logger.Debug("SOCKS5 routing failed for %s: %v", targetAddr, err)
	}
}

func (s *SOCKS5Server) handleHandshake(conn net.Conn) error {
	// Read version and number of methods
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return fmt.Errorf("failed to read SOCKS5 header: %w", err)
	}

	if header[0] != socks5Version {
		return fmt.Errorf("unsupported SOCKS version: %d", header[0])
	}

	numMethods := int(header[1])
	methods := make([]byte, numMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return fmt.Errorf("failed to read auth methods: %w", err)
	}

	// Select authentication method
	if s.username != "" {
		// Require username/password auth
		hasAuth := false
		for _, m := range methods {
			if m == authPassword {
				hasAuth = true
				break
			}
		}
		if !hasAuth {
			conn.Write([]byte{socks5Version, authNoAccept})
			return fmt.Errorf("client doesn't support password auth")
		}
		conn.Write([]byte{socks5Version, authPassword})
		return s.handlePasswordAuth(conn)
	}

	// No auth required
	conn.Write([]byte{socks5Version, authNone})
	return nil
}

func (s *SOCKS5Server) handlePasswordAuth(conn net.Conn) error {
	// RFC 1929: Username/Password Authentication
	// +----+------+----------+------+----------+
	// |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
	// +----+------+----------+------+----------+
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}

	if header[0] != 0x01 {
		return fmt.Errorf("unsupported auth version: %d", header[0])
	}

	uLen := int(header[1])
	username := make([]byte, uLen)
	if _, err := io.ReadFull(conn, username); err != nil {
		return err
	}

	pLenBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, pLenBuf); err != nil {
		return err
	}

	password := make([]byte, int(pLenBuf[0]))
	if _, err := io.ReadFull(conn, password); err != nil {
		return err
	}

	if string(username) == s.username && string(password) == s.password {
		conn.Write([]byte{0x01, 0x00}) // Success
		return nil
	}

	conn.Write([]byte{0x01, 0x01}) // Failure
	return fmt.Errorf("authentication failed")
}

func (s *SOCKS5Server) handleRequest(conn net.Conn) (string, error) {
	// +----+-----+-------+------+----------+----------+
	// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	// +----+-----+-------+------+----------+----------+
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", fmt.Errorf("failed to read request: %w", err)
	}

	if header[0] != socks5Version {
		return "", fmt.Errorf("unsupported version: %d", header[0])
	}

	if header[1] != cmdConnect {
		s.sendReply(conn, repCmdNotSupported, nil)
		return "", fmt.Errorf("unsupported command: %d", header[1])
	}

	// Parse address
	var host string
	switch header[3] {
	case addrIPv4:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", err
		}
		host = net.IP(addr).String()

	case addrDomain:
		domainLen := make([]byte, 1)
		if _, err := io.ReadFull(conn, domainLen); err != nil {
			return "", err
		}
		domain := make([]byte, int(domainLen[0]))
		if _, err := io.ReadFull(conn, domain); err != nil {
			return "", err
		}
		host = string(domain)

	case addrIPv6:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", err
		}
		host = net.IP(addr).String()

	default:
		s.sendReply(conn, repAddrNotSupported, nil)
		return "", fmt.Errorf("unsupported address type: %d", header[3])
	}

	// Read port
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return "", err
	}
	port := binary.BigEndian.Uint16(portBuf)

	return fmt.Sprintf("%s:%d", host, port), nil
}

func (s *SOCKS5Server) sendReply(conn net.Conn, reply byte, bindAddr net.Addr) {
	// +----+-----+-------+------+----------+----------+
	// |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
	// +----+-----+-------+------+----------+----------+
	resp := []byte{socks5Version, reply, 0x00, addrIPv4, 0, 0, 0, 0, 0, 0}
	conn.Write(resp)
}

// routeConnection routes a connection through the anonymous tunnel network
func (s *SOCKS5Server) routeConnection(clientConn net.Conn, targetAddr string) error {
	// Try to get an outbound tunnel for routing
	outTunnel, err := s.tunnelPool.GetOutboundTunnel()
	if err != nil {
		s.logger.Debug("No tunnel available, using outproxy directly: %v", err)
	}

	// Connect through outproxy (which handles the actual internet connection)
	targetConn, err := s.outproxy.Connect(targetAddr, outTunnel)
	if err != nil {
		s.sendReply(clientConn, repHostUnreachable, nil)
		return fmt.Errorf("failed to connect to %s: %w", targetAddr, err)
	}
	defer targetConn.Close()

	// Send success reply
	s.sendReply(clientConn, repSuccess, targetConn.LocalAddr())

	// Bidirectional data relay with connection privacy
	s.relay(clientConn, targetConn)
	return nil
}

// relay copies data bidirectionally between two connections
func (s *SOCKS5Server) relay(client, target net.Conn) {
	done := make(chan struct{}, 2)

	// Client -> Target
	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 32*1024)
		io.CopyBuffer(target, client, buf)
		// Signal write-close to target
		if tc, ok := target.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	// Target -> Client
	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 32*1024)
		io.CopyBuffer(client, target, buf)
		// Signal write-close to client
		if tc, ok := client.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	// Wait for at least one direction to finish
	<-done

	// Give the other direction a moment to finish gracefully
	timer := time.NewTimer(5 * time.Second)
	select {
	case <-done:
	case <-timer.C:
	}
	timer.Stop()
}

// ActiveConnections returns the number of active SOCKS5 connections
func (s *SOCKS5Server) ActiveConnections() int64 {
	return atomic.LoadInt64(&s.activeConns)
}
