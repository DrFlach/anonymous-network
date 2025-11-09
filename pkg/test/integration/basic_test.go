package integration

import (
    "testing"
    "time"

    "network/pkg/crypto"
    "network/pkg/router"
    "network/pkg/transport"
)

func TestBasicConnection(t *testing.T) {
    // Create two routers
    identity1, err := crypto.GenerateIdentity()
    if err != nil {
        t.Fatal(err)
    }
    
    identity2, err := crypto.GenerateIdentity()
    if err != nil {
        t.Fatal(err)
    }
    
    // Create transport managers
    tm1 := transport.NewManager(identity1, 10)
    tm2 := transport.NewManager(identity2, 10)
    
    // Start first router
    if err := tm1.Start("127.0.0.1:17656"); err != nil {
        t.Fatal(err)
    }
    defer tm1.Stop()
    
    // Start second router
    if err := tm2.Start("127.0.0.1:17657"); err != nil {
        t.Fatal(err)
    }
    defer tm2.Stop()
    
    // Connect router2 to router1
    if err := tm2.ConnectTo("127.0.0.1:17656"); err != nil {
        t.Fatal(err)
    }
    
    time.Sleep(100 * time.Millisecond)
    
    // Check connection
    if tm1.GetPeerCount() != 1 {
        t.Errorf("Expected 1 peer on router1, got %d", tm1.GetPeerCount())
    }
    
    if tm2.GetPeerCount() != 1 {
        t.Errorf("Expected 1 peer on router2, got %d", tm2.GetPeerCount())
    }
    
    t.Log("✓ Basic connection test passed")
}

func TestMessageExchange(t *testing.T) {
    // Create two routers
    identity1, _ := crypto.GenerateIdentity()
    identity2, _ := crypto.GenerateIdentity()
    
    tm1 := transport.NewManager(identity1, 10)
    tm2 := transport.NewManager(identity2, 10)
    
    tm1.Start("127.0.0.1:18656")
    tm2.Start("127.0.0.1:18657")
    defer tm1.Stop()
    defer tm2.Stop()
    
    tm2.ConnectTo("127.0.0.1:18656")
    time.Sleep(100 * time.Millisecond)
    
    // Send ping from router2 to router1
    ping := router.NewMessage(router.MsgTypePing, []byte("PING"))
    data, _ := ping.Serialize()
    
    peers := tm2.GetPeers()
    if len(peers) == 0 {
        t.Fatal("No peers connected")
    }
    
    tm2.SendToAddress(peers[0], data)
    
    // Receive on router1
    select {
    case msg := <-tm1.GetIncomingMessages():
        t.Logf("✓ Received message: %d bytes", len(msg.Data))
        
        parsed, err := router.Deserialize(msg.Data)
        if err != nil {
            t.Fatal(err)
        }
        
        if parsed.Type != router.MsgTypePing {
            t.Errorf("Expected ping, got type %d", parsed.Type)
        }
        
    case <-time.After(2 * time.Second):
        t.Fatal("Timeout waiting for message")
    }
}