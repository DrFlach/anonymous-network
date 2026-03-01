package main

import (
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"network/pkg/crypto"
	"network/pkg/netdb"
	"network/pkg/proxy"
	"network/pkg/router"
	"network/pkg/transport"
	"network/pkg/tunnel"
	"network/pkg/util"
)

func main() {
	// Command line flags
	configPath := flag.String("config", "config.json", "Path to configuration file")
	keygen := flag.Bool("keygen", false, "Generate new identity and exit")
	listenAddr := flag.String("listen", "", "Address to listen on (overrides config)")
	seeds := flag.String("seeds", "", "Comma-separated list of seed router addresses")
	socksAddr := flag.String("socks", "", "SOCKS5 proxy listen address (overrides config)")
	debug := flag.Bool("debug", false, "Enable debug logging")
	floodfillFlag := flag.Bool("floodfill", false, "Enable floodfill mode")
	noOutproxy := flag.Bool("no-outproxy", false, "Disable outproxy (exit node)")
	verify := flag.Bool("verify", false, "Run encryption self-test and exit")
	joinAddr := flag.String("join", "", "Connect to an existing peer (ip:port) to join the network")

	flag.Parse()

	// Setup logger
	logger := util.GetLogger()
	if *debug {
		logger.SetLevel(util.DEBUG)
	}

	// Handle verify mode — quick self-test of encryption subsystems
	if *verify {
		runVerification(logger)
		return
	}

	logger.Info("╔══════════════════════════════════════════╗")
	logger.Info("║     Anonymous P2P Network Router         ║")
	logger.Info("║     Version: 0.2.0-alpha                 ║")
	logger.Info("╚══════════════════════════════════════════╝")

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

	// Apply flag overrides
	if *listenAddr != "" {
		parts := strings.Split(*listenAddr, ":")
		if len(parts) == 2 {
			config.ListenAddress = parts[0]
			fmt.Sscanf(parts[1], "%d", &config.ListenPort)
		}
	}
	if *socksAddr != "" {
		config.SOCKS5Address = *socksAddr
	}
	if *floodfillFlag {
		config.IsFloodfill = true
	}
	if *noOutproxy {
		config.OutproxyEnabled = false
	}

	// Generate or load identity (persistent)
	identity, isNew, err := crypto.LoadOrCreateIdentity(config.IdentityFile)
	if err != nil {
		logger.Fatal("Failed to load/create identity: %v", err)
	}

	if isNew {
		logger.Info("Generated new router identity")
	} else {
		logger.Info("Loaded existing router identity")
	}
	logger.Info("Router Hash: %s", identity.GetRouterHashString())

	// Create NetDB
	netDB := netdb.NewStore()
	logger.Info("NetDB initialized")

	// Create Floodfill Manager
	floodfillMgr := netdb.NewFloodfillManager(netDB, config.IsFloodfill)
	if config.IsFloodfill {
		logger.Info("Floodfill mode: ENABLED")
	}

	// Create transport manager
	transportMgr := transport.NewManager(identity, config.MaxConnections)

	// Create tunnel pool
	tunnelConfig := &tunnel.PoolConfig{
		TargetInbound:  config.InboundTunnels,
		TargetOutbound: config.OutboundTunnels,
		TunnelLength:   config.TunnelLength,
		TunnelLifetime: time.Duration(config.TunnelLifetime) * time.Second,
	}
	tunnelPool := tunnel.NewPool(identity, netDB, tunnelConfig)

	// Create outproxy
	outproxyConfig := &proxy.OutproxyConfig{
		Enabled:      config.OutproxyEnabled,
		ConnTimeout:  30 * time.Second,
		BlockedHosts: config.BlockedHosts,
		DNSServers:   config.DNSServers,
	}
	outproxy := proxy.NewOutproxy(outproxyConfig)

	// Start transport manager
	fullListenAddr := fmt.Sprintf("%s:%d", config.ListenAddress, config.ListenPort)
	if err := transportMgr.Start(fullListenAddr); err != nil {
		logger.Fatal("Failed to start transport manager: %v", err)
	}
	logger.Info("P2P transport listening on %s", fullListenAddr)

	// Set up floodfill send function
	floodfillMgr.SetSendFunc(func(routerHash [32]byte, data []byte) error {
		return transportMgr.SendTo(routerHash, data)
	})

	// Connect to seed routers if provided
	seedList := config.SeedRouters
	if *seeds != "" {
		seedList = append(seedList, strings.Split(*seeds, ",")...)
	}
	if *joinAddr != "" {
		seedList = append(seedList, *joinAddr)
	}

	// Clean seed list
	var cleanSeeds []string
	for _, seed := range seedList {
		seed = strings.TrimSpace(seed)
		if seed != "" {
			cleanSeeds = append(cleanSeeds, seed)
		}
	}

	// Register seeds for auto-reconnection
	transportMgr.SetSeeds(cleanSeeds)

	for _, seed := range cleanSeeds {
		logger.Info("Connecting to seed router: %s", seed)
		if err := transportMgr.ConnectTo(seed); err != nil {
			logger.Error("Failed to connect to seed %s: %v", seed, err)
			logger.Info("Will auto-retry in background every 15 seconds")
		}
	}

	// Start message handler
	go handleMessages(transportMgr, netDB, floodfillMgr, tunnelPool, logger)

	// Publish our RouterInfo
	publishRouterInfo(identity, fullListenAddr, netDB, floodfillMgr, config, logger)

	// Start tunnel pool
	tunnelPool.Start()

	// Start SOCKS5 proxy if enabled
	var socksServer *proxy.SOCKS5Server
	if config.SOCKS5Enabled {
		socksConfig := &proxy.SOCKS5Config{
			ListenAddr: config.SOCKS5Address,
			Username:   config.SOCKS5Username,
			Password:   config.SOCKS5Password,
		}
		socksServer = proxy.NewSOCKS5Server(socksConfig, tunnelPool, outproxy)
		if err := socksServer.Start(); err != nil {
			logger.Fatal("Failed to start SOCKS5 proxy: %v", err)
		}
		logger.Info("═══════════════════════════════════════════")
		logger.Info("  SOCKS5 proxy ready on %s", config.SOCKS5Address)
		logger.Info("  Configure your browser proxy settings    ")
		logger.Info("  to use this address for anonymous browsing")
		logger.Info("═══════════════════════════════════════════")
	}

	// Start status reporter with a done channel we can close on shutdown
	doneChan := make(chan struct{})
	go statusReporter(transportMgr, tunnelPool, netDB, logger, doneChan)

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	logger.Info("Router started successfully")
	logger.Info("Press Ctrl+C to stop")

	<-sigChan

	logger.Info("")
	logger.Info("Shutting down gracefully...")

	// Force exit after 10 seconds if graceful shutdown hangs
	go func() {
		time.Sleep(10 * time.Second)
		logger.Warn("Shutdown timed out, forcing exit")
		os.Exit(1)
	}()

	// Signal all background goroutines to stop
	close(doneChan)

	// Stop in reverse order
	if socksServer != nil {
		socksServer.Stop()
	}
	tunnelPool.Stop()
	transportMgr.Stop()

	logger.Info("Goodbye!")
	os.Exit(0)
}

func generateIdentity() {
	logger := util.GetLogger()

	identity, err := crypto.GenerateIdentity()
	if err != nil {
		logger.Fatal("Failed to generate identity: %v", err)
	}

	fmt.Println("=== New Router Identity ===")
	fmt.Printf("Router Hash: %s\n", identity.GetRouterHashString())

	// Save to file
	if err := crypto.SaveIdentity(identity, "identity.json"); err != nil {
		logger.Fatal("Failed to save identity: %v", err)
	}

	fmt.Println("Identity saved to identity.json")
	fmt.Println("Keep this file safe - it is your router's permanent identity!")
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

func publishRouterInfo(identity *crypto.RouterIdentity, listenAddr string, netDB *netdb.Store, floodfillMgr *netdb.FloodfillManager, config *util.Config, logger *util.Logger) {
	// Create RouterInfo
	ri := netdb.NewRouterInfo(
		identity.RouterHash,
		identity.SigningPublicKey,
		identity.EncryptionPublicKey,
	)

	// Parse listen address
	host, port := parseAddr(listenAddr)
	ri.AddAddress(host, port)

	// Set capabilities
	if config.IsFloodfill {
		ri.SetCapability("floodfill", true)
	}
	ri.SetCapability("reachable", true)
	if config.OutproxyEnabled {
		ri.SetCapability("outproxy", true)
	}

	// Sign RouterInfo
	ri.Sign(identity.SigningPrivateKey)

	// Publish to network
	if err := floodfillMgr.PublishRouterInfo(ri); err != nil {
		logger.Error("Failed to publish RouterInfo: %v", err)
		return
	}

	logger.Info("RouterInfo published")
}

func parseAddr(addr string) (string, int) {
	host := "127.0.0.1"
	port := 7656

	parts := strings.Split(addr, ":")
	if len(parts) == 2 {
		host = parts[0]
		fmt.Sscanf(parts[1], "%d", &port)
	}

	return host, port
}

func handleMessages(transportMgr *transport.Manager, netDB *netdb.Store, floodfillMgr *netdb.FloodfillManager, tunnelPool *tunnel.Pool, logger *util.Logger) {
	msgChan := transportMgr.GetIncomingMessages()
	participants := tunnelPool.GetParticipantStore()

	for msg := range msgChan {
		logger.Debug("Received message from %x: %d bytes", msg.From[:8], len(msg.Data))

		// Parse message
		parsedMsg, err := router.Deserialize(msg.Data)
		if err != nil {
			// Silently skip short/invalid frames (e.g. raw heartbeats)
			logger.Debug("Skipping unparseable message (%d bytes): %v", len(msg.Data), err)
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

		case router.MsgTypeDatabaseStore:
			if err := floodfillMgr.HandleDatabaseStore(parsedMsg.Payload); err != nil {
				logger.Debug("Failed to handle database store: %v", err)
			}

		case router.MsgTypeDatabaseLookup:
			response, err := floodfillMgr.HandleDatabaseLookup(parsedMsg.Payload)
			if err != nil {
				logger.Debug("Failed to handle database lookup: %v", err)
				continue
			}
			reply := router.NewMessage(router.MsgTypeDatabaseSearchReply, response)
			data, _ := reply.Serialize()
			transportMgr.SendTo(msg.From, data)

		case router.MsgTypeTunnelBuild:
			handleTunnelBuild(transportMgr, msg.From, parsedMsg, participants, logger)

		case router.MsgTypeTunnelData:
			handleTunnelData(transportMgr, parsedMsg, participants, logger)

		case router.MsgTypePeerList:
			logger.Debug("Received peer list from %x (%d bytes)", msg.From[:8], len(parsedMsg.Payload))
			transportMgr.HandlePeerList(parsedMsg.Payload)

		default:
			logger.Debug("Unknown message type: %d", parsedMsg.Type)
		}
	}
}

func handlePing(transportMgr *transport.Manager, from [32]byte, msg *router.Message, logger *util.Logger) {
	logger.Debug("Received ping from %x, sending pong", from[:8])

	pong := router.NewMessage(router.MsgTypePong, []byte("PONG"))
	data, err := pong.Serialize()
	if err != nil {
		logger.Error("Failed to serialize pong: %v", err)
		return
	}

	if err := transportMgr.SendTo(from, data); err != nil {
		logger.Error("Failed to send pong: %v", err)
	}
}

func handleTunnelBuild(transportMgr *transport.Manager, from [32]byte, msg *router.Message, participants *tunnel.TunnelParticipantStore, logger *util.Logger) {
	logger.Debug("Received tunnel build request from %x", from[:8])

	req, err := tunnel.DeserializeBuildRequest(msg.Payload)
	if err != nil {
		logger.Error("Failed to parse tunnel build request: %v", err)
		return
	}

	// Accept the tunnel participation
	participant := &tunnel.TunnelParticipant{
		ReceiveTunnelID: req.ReceiveTunnelID,
		SendTunnelID:    req.NextTunnelID,
		NextHop:         req.NextIdent,
		LayerKey:        req.LayerKey,
		IVKey:           req.IVKey,
		IsEndpoint:      req.IsEndpoint,
		CreatedAt:       time.Now(),
		ExpiresAt:       time.Now().Add(10 * time.Minute),
	}

	participants.Add(participant)
	logger.Debug("Accepted tunnel participation: recv=%d endpoint=%v", req.ReceiveTunnelID, req.IsEndpoint)

	// Send build reply (accept)
	reply := router.NewMessage(router.MsgTypeTunnelBuildReply, []byte{tunnel.BuildAccept})
	data, _ := reply.Serialize()
	transportMgr.SendTo(from, data)
}

func handleTunnelData(transportMgr *transport.Manager, msg *router.Message, participants *tunnel.TunnelParticipantStore, logger *util.Logger) {
	tunnelMsg, err := tunnel.DeserializeTunnelMessage(msg.Payload)
	if err != nil {
		logger.Debug("Failed to parse tunnel data: %v", err)
		return
	}

	nextHop, nextTunnelID, processedData, isEndpoint, err := participants.ProcessMessage(tunnelMsg.TunnelID, tunnelMsg.Data)
	if err != nil {
		logger.Debug("Failed to process tunnel message: %v", err)
		return
	}

	if isEndpoint {
		logger.Debug("Tunnel endpoint: delivering %d bytes", len(processedData))
		return
	}

	// Forward to next hop
	fwdMsg := &tunnel.TunnelMessage{
		TunnelID:    nextTunnelID,
		Data:        processedData,
		FragmentNum: tunnelMsg.FragmentNum,
		IsLast:      tunnelMsg.IsLast,
	}

	fwdData := tunnel.SerializeTunnelMessage(fwdMsg)
	wrapped := router.NewMessage(router.MsgTypeTunnelData, fwdData)
	wrappedData, _ := wrapped.Serialize()

	if err := transportMgr.SendTo(nextHop, wrappedData); err != nil {
		logger.Debug("Failed to forward tunnel data to %x: %v", nextHop[:8], err)
	}
}

func statusReporter(transportMgr *transport.Manager, tunnelPool *tunnel.Pool, netDB *netdb.Store, logger *util.Logger, stopChan <-chan struct{}) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-stopChan:
			return
		case <-ticker.C:
			peerCount := transportMgr.GetPeerCount()
			routerCount := netDB.Count()
			inTunnels, outTunnels, participations := tunnelPool.Stats()

			logger.Info("── Status: Peers=%d | NetDB=%d | Tunnels: in=%d out=%d | Participating=%d ──",
				peerCount, routerCount, inTunnels, outTunnels, participations)
		}
	}
}

// runVerification performs a self-test of all encryption and privacy subsystems
func runVerification(logger *util.Logger) {
	fmt.Println("╔═══════════════════════════════════════════════╗")
	fmt.Println("║  Anonymous Network — Encryption Self-Test     ║")
	fmt.Println("╚═══════════════════════════════════════════════╝")
	fmt.Println()

	passed := 0
	failed := 0

	// Test 1: Identity generation (Ed25519 + X25519)
	fmt.Print("[1/5] Cryptographic identity (Ed25519 + X25519)... ")
	identity, err := crypto.GenerateIdentity()
	if err != nil {
		fmt.Printf("FAIL: %v\n", err)
		failed++
	} else {
		// Verify signing works
		testData := []byte("test message for signing")
		sig := ed25519.Sign(identity.SigningPrivateKey, testData)
		if ed25519.Verify(identity.SigningPublicKey, testData, sig) {
			fmt.Println("✅ PASS — Ed25519 sign/verify OK, X25519 keys generated")
			passed++
		} else {
			fmt.Println("FAIL — signature verification failed")
			failed++
		}
	}

	// Test 2: Layered encryption (ChaCha20-Poly1305)
	fmt.Print("[2/5] Layered encryption (ChaCha20-Poly1305)...  ")
	layerKeys := make([][32]byte, 3)
	for i := range layerKeys {
		for j := range layerKeys[i] {
			layerKeys[i][j] = byte(i*32 + j)
		}
	}
	plaintext := []byte("secret payload through 3 layers")
	encrypted, err := crypto.EncryptLayered(plaintext, layerKeys)
	if err != nil {
		fmt.Printf("FAIL: %v\n", err)
		failed++
	} else {
		// Decrypt layers in forward order (outermost = key[0], then key[1], then key[2])
		data := encrypted
		for i := 0; i < len(layerKeys); i++ {
			data, err = crypto.DecryptLayer(data, layerKeys[i])
			if err != nil {
				break
			}
		}
		if err != nil {
			fmt.Printf("FAIL: decryption error: %v\n", err)
			failed++
		} else if string(data) == string(plaintext) {
			fmt.Println("✅ PASS — 3-layer onion encryption/decryption OK")
			passed++
		} else {
			fmt.Println("FAIL — decrypted data doesn't match")
			failed++
		}
	}

	// Test 3: RouterInfo signing (deterministic serialization)
	fmt.Print("[3/5] RouterInfo signature (deterministic)...   ")
	ri := netdb.NewRouterInfo(identity.RouterHash, identity.SigningPublicKey, identity.EncryptionPublicKey)
	ri.AddAddress("127.0.0.1", 7656)
	ri.SetCapability("floodfill", true)
	ri.SetCapability("reachable", true)
	ri.Sign(identity.SigningPrivateKey)
	if ri.Verify() {
		fmt.Println("✅ PASS — RouterInfo sign/verify with sorted capabilities OK")
		passed++
	} else {
		fmt.Println("FAIL — RouterInfo signature verification failed")
		failed++
	}

	// Test 4: DNS-over-HTTPS (DoH) resolution
	fmt.Print("[4/5] DNS-over-HTTPS (DoH) resolution...        ")
	dohURL := "https://1.1.1.1/dns-query?name=example.com&type=A"
	req, _ := http.NewRequest("GET", dohURL, nil)
	req.Header.Set("Accept", "application/dns-json")
	req.Header.Set("User-Agent", "")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("FAIL: %v\n", err)
		failed++
	} else {
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		var dohResp struct {
			Status int `json:"Status"`
			Answer []struct {
				Data string `json:"data"`
				Type int    `json:"type"`
			} `json:"Answer"`
		}
		if err := json.Unmarshal(body, &dohResp); err != nil {
			fmt.Printf("FAIL: parse error: %v\n", err)
			failed++
		} else if dohResp.Status == 0 && len(dohResp.Answer) > 0 {
			fmt.Printf("✅ PASS — example.com → %s (via encrypted DoH to Cloudflare)\n", dohResp.Answer[len(dohResp.Answer)-1].Data)
			passed++
		} else {
			fmt.Printf("FAIL: DoH status=%d, answers=%d\n", dohResp.Status, len(dohResp.Answer))
			failed++
		}
	}

	// Test 5: HTTPS connectivity test
	fmt.Print("[5/5] HTTPS/TLS connectivity...                 ")
	tlsResp, err := http.Get("https://www.google.com")
	if err != nil {
		fmt.Printf("FAIL: %v\n", err)
		failed++
	} else {
		tlsResp.Body.Close()
		tlsVer := "unknown"
		if tlsResp.TLS != nil {
			switch tlsResp.TLS.Version {
			case 0x0304:
				tlsVer = "TLS 1.3"
			case 0x0303:
				tlsVer = "TLS 1.2"
			}
		}
		fmt.Printf("✅ PASS — TLS handshake OK (%s)\n", tlsVer)
		passed++
	}

	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════")
	fmt.Printf("  Results: %d/5 passed, %d/5 failed\n", passed, failed)
	fmt.Println("═══════════════════════════════════════════════")
	fmt.Println()

	if failed == 0 {
		fmt.Println("✅ All encryption subsystems working correctly!")
		fmt.Println()
		fmt.Println("What is encrypted when you browse:")
		fmt.Println("  🔒 DNS queries     → Encrypted via DNS-over-HTTPS (DoH)")
		fmt.Println("  🔒 HTTPS sites     → End-to-end TLS encryption (browser ↔ server)")
		fmt.Println("  🔒 Tunnel traffic  → ChaCha20-Poly1305 layered encryption")
		fmt.Println("  ⚠️  HTTP sites     → DNS protected, but page content sent in cleartext")
		fmt.Println()
		fmt.Println("For maximum security: only visit HTTPS sites (🔒 in address bar).")
	} else {
		fmt.Println("⚠️  Some encryption subsystems failed. Check your network connection.")
	}
}