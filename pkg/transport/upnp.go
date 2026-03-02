package transport

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"network/pkg/util"
)

// UPnPManager handles automatic port forwarding via UPnP IGD protocol.
// Most home routers support this — it automatically opens the port so
// other peers from the internet can connect directly.
type UPnPManager struct {
	serviceURL  string
	serviceType string
	externalIP  string
	localIP     string
	port        int
	active      bool
	logger      *util.Logger
}

// NewUPnPManager creates a new UPnP port forwarding manager
func NewUPnPManager() *UPnPManager {
	return &UPnPManager{
		logger: util.GetLogger(),
	}
}

// ForwardPort attempts to forward an external port to the local machine via UPnP.
// Returns nil on success, error if UPnP is not available or failed.
func (u *UPnPManager) ForwardPort(port int) error {
	u.port = port

	// Step 1: Get our local IP
	localIP, err := getOutboundIP()
	if err != nil {
		return fmt.Errorf("failed to determine local IP: %w", err)
	}
	u.localIP = localIP
	u.logger.Info("UPnP: Local IP is %s", localIP)

	// Step 2: Discover UPnP gateway via SSDP
	serviceURL, serviceType, err := u.discoverGateway()
	if err != nil {
		return fmt.Errorf("UPnP discovery failed: %w", err)
	}
	u.serviceURL = serviceURL
	u.serviceType = serviceType
	u.logger.Info("UPnP: Found gateway at %s", serviceURL)

	// Step 3: Get external IP from router
	extIP, err := u.getExternalIP()
	if err != nil {
		u.logger.Debug("UPnP: Could not get external IP: %v", err)
		// Not fatal — we can still try to add the mapping
	} else {
		u.externalIP = extIP
		u.logger.Info("UPnP: External IP is %s", extIP)
	}

	// Step 4: Add port mapping
	if err := u.addPortMapping(port, localIP); err != nil {
		return fmt.Errorf("UPnP port mapping failed: %w", err)
	}

	u.active = true
	u.logger.Info("UPnP: Port %d forwarded successfully (%s → %s:%d)", port, u.externalIP, localIP, port)
	return nil
}

// ClearPort removes the port forwarding rule
func (u *UPnPManager) ClearPort() {
	if !u.active || u.serviceURL == "" {
		return
	}

	if err := u.deletePortMapping(u.port); err != nil {
		u.logger.Debug("UPnP: Failed to remove port mapping: %v", err)
	} else {
		u.logger.Info("UPnP: Port %d forwarding removed", u.port)
	}
	u.active = false
}

// GetExternalIP returns the external IP discovered via UPnP
func (u *UPnPManager) GetExternalIP() string {
	return u.externalIP
}

// IsActive returns whether UPnP port forwarding is active
func (u *UPnPManager) IsActive() bool {
	return u.active
}

// ── SSDP Discovery ───────────────────────────────────────────────────────────

// getDefaultGateway finds the default gateway IP by reading /proc/net/route
func getDefaultGateway() string {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return ""
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines[1:] { // skip header
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		// Destination == 00000000 means default route
		if fields[1] == "00000000" {
			// Gateway is hex-encoded IP in little-endian
			gw := fields[2]
			if len(gw) == 8 {
				a, b, c, d := hexByte(gw[6:8]), hexByte(gw[4:6]), hexByte(gw[2:4]), hexByte(gw[0:2])
				return fmt.Sprintf("%d.%d.%d.%d", a, b, c, d)
			}
		}
	}
	return ""
}

func hexByte(s string) int {
	var v int
	fmt.Sscanf(s, "%x", &v)
	return v
}

// discoverGateway sends an SSDP M-SEARCH to find a UPnP IGD device.
// Tries multicast first, then falls back to unicast directly to the gateway.
func (u *UPnPManager) discoverGateway() (serviceURL, serviceType string, err error) {
	searchTargets := []string{
		"urn:schemas-upnp-org:service:WANIPConnection:1",
		"urn:schemas-upnp-org:service:WANIPConnection:2",
		"urn:schemas-upnp-org:service:WANPPPConnection:1",
	}

	// Destinations: multicast first, then unicast to default gateway
	destinations := []string{"239.255.255.250:1900"}
	if gw := getDefaultGateway(); gw != "" {
		destinations = append(destinations, gw+":1900")
		u.logger.Debug("UPnP: Will also try unicast to gateway %s", gw)
	}

	for _, st := range searchTargets {
		msg := "M-SEARCH * HTTP/1.1\r\n" +
			"HOST: 239.255.255.250:1900\r\n" +
			"ST: " + st + "\r\n" +
			"MAN: \"ssdp:discover\"\r\n" +
			"MX: 2\r\n" +
			"\r\n"

		for _, dest := range destinations {
			addr, _ := net.ResolveUDPAddr("udp4", dest)
			conn, err := net.ListenUDP("udp4", nil)
			if err != nil {
				continue
			}

			conn.SetDeadline(time.Now().Add(2 * time.Second))
			conn.WriteTo([]byte(msg), addr)

			buf := make([]byte, 4096)
			n, _, err := conn.ReadFrom(buf)
			conn.Close()
			if err != nil {
				continue
			}

			response := string(buf[:n])
			location := extractHeader(response, "LOCATION")
			if location == "" {
				location = extractHeader(response, "Location")
			}
			if location == "" {
				continue
			}

			// Fetch the device description XML to find the control URL
			svcURL, svcType, err := u.parseDeviceDescription(location)
			if err != nil {
				u.logger.Debug("UPnP: Failed to parse device at %s: %v", location, err)
				continue
			}
			if svcURL != "" {
				return svcURL, svcType, nil
			}
		}
	}

	return "", "", fmt.Errorf("no UPnP gateway found on local network")
}

// ── XML Device Description Parsing ───────────────────────────────────────────

type upnpRoot struct {
	XMLName xml.Name   `xml:"root"`
	Device  upnpDevice `xml:"device"`
}

type upnpDevice struct {
	DeviceType  string         `xml:"deviceType"`
	DeviceList  []upnpDevice   `xml:"deviceList>device"`
	ServiceList []upnpService  `xml:"serviceList>service"`
}

type upnpService struct {
	ServiceType string `xml:"serviceType"`
	ControlURL  string `xml:"controlURL"`
}

func (u *UPnPManager) parseDeviceDescription(location string) (controlURL, serviceType string, err error) {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(location)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", err
	}

	var root upnpRoot
	if err := xml.Unmarshal(body, &root); err != nil {
		return "", "", err
	}

	// Search for WANIPConnection or WANPPPConnection service
	wantTypes := []string{
		"urn:schemas-upnp-org:service:WANIPConnection:1",
		"urn:schemas-upnp-org:service:WANIPConnection:2",
		"urn:schemas-upnp-org:service:WANPPPConnection:1",
	}

	// Get base URL from location
	baseURL := location
	if idx := strings.Index(location[8:], "/"); idx >= 0 {
		baseURL = location[:8+idx]
	}

	// Recursively search devices and sub-devices
	var search func(d upnpDevice) (string, string)
	search = func(d upnpDevice) (string, string) {
		for _, svc := range d.ServiceList {
			for _, want := range wantTypes {
				if svc.ServiceType == want {
					ctrlURL := svc.ControlURL
					if !strings.HasPrefix(ctrlURL, "http") {
						if !strings.HasPrefix(ctrlURL, "/") {
							ctrlURL = "/" + ctrlURL
						}
						ctrlURL = baseURL + ctrlURL
					}
					return ctrlURL, svc.ServiceType
				}
			}
		}
		for _, sub := range d.DeviceList {
			if url, st := search(sub); url != "" {
				return url, st
			}
		}
		return "", ""
	}

	url, st := search(root.Device)
	return url, st, nil
}

// ── SOAP Actions ─────────────────────────────────────────────────────────────

func (u *UPnPManager) addPortMapping(port int, localIP string) error {
	body := fmt.Sprintf(`<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:AddPortMapping xmlns:u="%s">
      <NewRemoteHost></NewRemoteHost>
      <NewExternalPort>%d</NewExternalPort>
      <NewProtocol>TCP</NewProtocol>
      <NewInternalPort>%d</NewInternalPort>
      <NewInternalClient>%s</NewInternalClient>
      <NewEnabled>1</NewEnabled>
      <NewPortMappingDescription>AnonP2PNetwork</NewPortMappingDescription>
      <NewLeaseDuration>0</NewLeaseDuration>
    </u:AddPortMapping>
  </s:Body>
</s:Envelope>`, u.serviceType, port, port, localIP)

	action := fmt.Sprintf(`"%s#AddPortMapping"`, u.serviceType)
	return u.soapRequest(body, action)
}

func (u *UPnPManager) deletePortMapping(port int) error {
	body := fmt.Sprintf(`<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:DeletePortMapping xmlns:u="%s">
      <NewRemoteHost></NewRemoteHost>
      <NewExternalPort>%d</NewExternalPort>
      <NewProtocol>TCP</NewProtocol>
    </u:DeletePortMapping>
  </s:Body>
</s:Envelope>`, u.serviceType, port)

	action := fmt.Sprintf(`"%s#DeletePortMapping"`, u.serviceType)
	return u.soapRequest(body, action)
}

func (u *UPnPManager) getExternalIP() (string, error) {
	body := fmt.Sprintf(`<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:GetExternalIPAddress xmlns:u="%s">
    </u:GetExternalIPAddress>
  </s:Body>
</s:Envelope>`, u.serviceType)

	action := fmt.Sprintf(`"%s#GetExternalIPAddress"`, u.serviceType)

	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest("POST", u.serviceURL, bytes.NewReader([]byte(body)))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "text/xml; charset=\"utf-8\"")
	req.Header.Set("SOAPAction", action)

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	// Extract IP from response
	ipStr := extractXMLValue(string(respBody), "NewExternalIPAddress")
	if ipStr == "" {
		return "", fmt.Errorf("no external IP in response")
	}
	return ipStr, nil
}

// ── Helpers ──────────────────────────────────────────────────────────────────

func (u *UPnPManager) soapRequest(body, action string) error {
	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest("POST", u.serviceURL, bytes.NewReader([]byte(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "text/xml; charset=\"utf-8\"")
	req.Header.Set("SOAPAction", action)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("SOAP error %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}

func extractHeader(response, header string) string {
	lines := strings.Split(response, "\r\n")
	for _, line := range lines {
		if strings.HasPrefix(strings.ToLower(line), strings.ToLower(header)+":") {
			return strings.TrimSpace(line[len(header)+1:])
		}
	}
	return ""
}

func extractXMLValue(xmlStr, tag string) string {
	start := strings.Index(xmlStr, "<"+tag+">")
	if start < 0 {
		return ""
	}
	start += len(tag) + 2
	end := strings.Index(xmlStr[start:], "</"+tag+">")
	if end < 0 {
		return ""
	}
	return xmlStr[start : start+end]
}

// getOutboundIP finds our local IP by making a UDP "connection" to a public address.
// No actual packets are sent — this just determines which interface would be used.
func getOutboundIP() (string, error) {
	conn, err := net.Dial("udp4", "8.8.8.8:80")
	if err != nil {
		return "", err
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String(), nil
}
