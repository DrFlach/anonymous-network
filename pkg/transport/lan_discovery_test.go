package transport

import (
	"encoding/base64"
	"net"
	"testing"

	"network/pkg/crypto"
)

func TestLANDiscoveryPacketTracksReachablePrivatePeer(t *testing.T) {
	identity, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}

	m := NewManager(identity, 10)
	m.listenPort = 7656

	localAddr := firstPrivateLocalAddr(t, m.listenPort)
	foreignHash := identity.RouterHash
	foreignHash[0] ^= 0xFF

	m.handleLANDiscoveryPacket(lanDiscoveryPacket{
		Magic:      lanDiscoveryMagic,
		RouterHash: base64.RawStdEncoding.EncodeToString(foreignHash[:]),
		Addrs:      []string{"bad-address", "8.8.8.8:7656", localAddr},
	}, &net.UDPAddr{IP: net.ParseIP("192.168.1.2"), Port: 7656})

	if got := m.GetKnownNodeCount(); got != 1 {
		t.Fatalf("expected one LAN-discovered node, got %d", got)
	}

	// Self-announcements must not add our own addresses as peers.
	m.handleLANDiscoveryPacket(lanDiscoveryPacket{
		Magic:      lanDiscoveryMagic,
		RouterHash: base64.RawStdEncoding.EncodeToString(identity.RouterHash[:]),
		Addrs:      []string{localAddr},
	}, &net.UDPAddr{IP: net.ParseIP("192.168.1.3"), Port: 7656})

	if got := m.GetKnownNodeCount(); got != 1 {
		t.Fatalf("self-announcement changed known nodes, got %d", got)
	}
}

func TestLANDiscoveryBroadcastTargetsIncludeGlobalBroadcast(t *testing.T) {
	identity, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}

	m := NewManager(identity, 10)
	m.listenPort = 7656

	targets := m.lanBroadcastTargets()
	for _, target := range targets {
		if target.String() == "255.255.255.255:7656" {
			return
		}
	}
	t.Fatalf("global broadcast target missing from %v", targets)
}

func firstPrivateLocalAddr(t *testing.T, port int) string {
	t.Helper()

	ifaces, err := net.Interfaces()
	if err != nil {
		t.Skipf("network interfaces unavailable: %v", err)
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipnet.IP.To4()
			if ip != nil && ip.IsPrivate() {
				return net.JoinHostPort(ip.String(), "7656")
			}
		}
	}

	t.Skipf("no private IPv4 interface available for LAN discovery test on port %d", port)
	return ""
}
