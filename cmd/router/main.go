package main

import (
    "flag"
    "fmt"
    "os"
    "os/signal"
    "syscall"

    "network/pkg/crypto"
    "network/pkg/netdb"
    "network/pkg/router"
    "network/pkg/transport"
    "network/pkg/util"
)

func main() {
    // Command line flags
    configPath := flag.String("config", "config.json", "Path to configuration file")
    keygen := flag.Bool("keygen", false, "Generate new identity and exit")
    listenAddr := flag.String("listen", "127.0.0.1:7656", "Address to listen on")
    seeds := flag.String("seeds", "", "Comma-separated list of seed router addresses")
    debug := flag.Bool("debug", false, "Enable debug logging")
    
    flag.Parse()
    
    // Setup logger
    logger := util.GetLogger()
    if *debug {
        logger.SetLevel(util.DEBUG)
    }
    
    logger.Info("=== Anonymous P2P Network Router ===")
    logger.Info("Version: MVP 0.1")
    
    // Handle keygen mode
    if *keygen {
        generateIdentity()
        return
    }
    
    // Load or create config
    config, err := loadOrCreateConfig(*configPath)
    if err != nil {
        logger.Fatal("Failed to load config: %v", err)
    }
    
    // Generate or load identity
    identity, err := crypto.GenerateIdentity()
    if err != nil {
        logger.Fatal("Failed to generate identity: %v", err)
    }
    
    logger.Info("Router Hash: %s", identity.GetRouterHashString())
    
    // Create NetDB
    netDB := netdb.NewStore()
    logger.Info("NetDB initialized")
    
    // Create transport manager
    transportMgr := transport.NewManager(identity, config.MaxConnections)
    
    // Start transport manager
    if err := transportMgr.Start(*listenAddr); err != nil {
        logger.Fatal("Failed to start transport manager: %v", err)
    }
    
    logger.Info("Listening on %s", *listenAddr)
    
    // Connect to seed routers if provided
    if *seeds != "" {
        logger.Info("Connecting to seed routers...")
        // Parse and connect to seeds
        // TODO: Parse comma-separated list
    }
    
    // Start message handler
    go handleMessages(transportMgr, netDB, logger)
    
    // Publish our RouterInfo
    publishRouterInfo(identity, *listenAddr, netDB, logger)
    
    // Wait for interrupt signal
    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
    
    logger.Info("Router started successfully")
    logger.Info("Press Ctrl+C to stop")
    
    <-sigChan
    
    logger.Info("Shutting down...")
    transportMgr.Stop()
    logger.Info("Goodbye!")
}

func generateIdentity() {
    logger := util.GetLogger()
    
    identity, err := crypto.GenerateIdentity()
    if err != nil {
        logger.Fatal("Failed to generate identity: %v", err)
    }
    
    fmt.Println("=== New Router Identity ===")
    fmt.Printf("Router Hash: %s\n", identity.GetRouterHashString())
    fmt.Println("\nIdentity generated successfully!")
    fmt.Println("Note: In production, this should be saved to disk")
}

func loadOrCreateConfig(path string) (*util.Config, error) {
    config, err := util.LoadConfig(path)
    if err != nil {
        // Create default config
        config = util.DefaultConfig()
        if err := config.Save(path); err != nil {
            return nil, err
        }
        util.GetLogger().Info("Created default config at %s", path)
    }
    return config, nil
}

func publishRouterInfo(identity *crypto.RouterIdentity, listenAddr string, netDB *netdb.Store, logger *util.Logger) {
    // Create RouterInfo
    ri := netdb.NewRouterInfo(
        identity.RouterHash,
        identity.SigningPublicKey,
        identity.EncryptionPublicKey,
    )
    
    // Parse listen address
    host := listenAddr[:len(listenAddr)-5] // Remove port for now (simple parsing)
    port := 7656
    ri.AddAddress(host, port)
    
    // Sign RouterInfo
    ri.Sign(identity.SigningPrivateKey)
    
    // Add to NetDB
    if err := netDB.Add(ri); err != nil {
        logger.Error("Failed to add RouterInfo to NetDB: %v", err)
        return
    }
    
    logger.Info("RouterInfo published to NetDB")
}

func handleMessages(transportMgr *transport.Manager, netDB *netdb.Store, logger *util.Logger) {
    msgChan := transportMgr.GetIncomingMessages()
    
    for msg := range msgChan {
        logger.Debug("Received message from %x: %d bytes", msg.From[:8], len(msg.Data))
        
        // Parse message
        parsedMsg, err := router.Deserialize(msg.Data)
        if err != nil {
            logger.Error("Failed to parse message: %v", err)
            continue
        }
        
        if parsedMsg.IsExpired() {
            logger.Debug("Message expired, dropping")
            continue
        }
        
        // Handle message based on type
        switch parsedMsg.Type {
        case router.MsgTypePing:
            handlePing(transportMgr, msg.From, parsedMsg, logger)
        case router.MsgTypePong:
            logger.Debug("Received pong from %x", msg.From[:8])
        default:
            logger.Debug("Unknown message type: %d", parsedMsg.Type)
        }
    }
}

func handlePing(transportMgr *transport.Manager, from [32]byte, msg *router.Message, logger *util.Logger) {
    logger.Debug("Received ping from %x, sending pong", from[:8])
    
    // Create pong response
    pong := router.NewMessage(router.MsgTypePong, []byte("PONG"))
    data, err := pong.Serialize()
    if err != nil {
        logger.Error("Failed to serialize pong: %v", err)
        return
    }
    
    // Send pong
    if err := transportMgr.SendTo(from, data); err != nil {
        logger.Error("Failed to send pong: %v", err)
    }
}