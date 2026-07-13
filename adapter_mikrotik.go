// ForgeAI Connector Host — MikroTik RouterOS Adapter (read-only)
//
// Collects system, interface, bridge, routing, firewall, DHCP, DNS,
// neighbor, wireless, and health data from MikroTik RouterOS devices
// via the REST API (RouterOS 7.1+). Falls back to the RouterOS API
// (/api/) for older firmware.
//
// Supports: routers, CRS switches, wireless APs, CHR virtual routers.
// Does NOT support SwOS devices.

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

type MikroTikAdapter struct {
	profile  *TargetProfile
	client   *http.Client
	baseURL  string
	user     string
	pass     string
	useREST  bool // true = REST API, false = RouterOS API (/api/)
}

func NewMikroTikAdapter(profile *TargetProfile) (TargetAdapter, error) {
	return &MikroTikAdapter{profile: profile}, nil
}

func (a *MikroTikAdapter) Init(profile *TargetProfile, creds map[string]string) error {
	a.profile = profile
	a.baseURL = strings.TrimRight(profile.Endpoint, "/")
	a.user = creds["username"]
	a.pass = creds["password"]

	timeout := 15 * time.Second
	if profile.ResourceLimits.TimeoutSecs > 0 {
		timeout = time.Duration(profile.ResourceLimits.TimeoutSecs) * time.Second
	}
	if timeout > 30*time.Second {
		timeout = 30 * time.Second
	}
	a.client = NewHTTPClientFromProfile(profile, timeout)

	// Probe REST API first (RouterOS 7.1+)
	log.Printf("[mikrotik:%s] Probing REST API at %s...", profile.Name, a.baseURL)
	_, err := a.mikrotikGet("/rest/system/identity")
	if err == nil {
		a.useREST = true
		log.Printf("[mikrotik:%s] Connected via REST API", profile.Name)
		return nil
	}

	// Fallback: try RouterOS API path (/api/)
	log.Printf("[mikrotik:%s] REST unavailable (%v), trying /api/ path...", profile.Name, err)
	_, err2 := a.mikrotikGet("/api/system/identity")
	if err2 == nil {
		a.useREST = false
		log.Printf("[mikrotik:%s] Connected via RouterOS /api/ path", profile.Name)
		return nil
	}

	// If HTTPS fails, try HTTP fallback
	if strings.HasPrefix(a.baseURL, "https://") {
		httpURL := "http://" + strings.TrimPrefix(a.baseURL, "https://")
		log.Printf("[mikrotik:%s] HTTPS failed, trying HTTP fallback at %s...", profile.Name, httpURL)
		a.baseURL = httpURL
		_, err3 := a.mikrotikGet("/rest/system/identity")
		if err3 == nil {
			a.useREST = true
			log.Printf("[mikrotik:%s] Connected via HTTP REST API", profile.Name)
			return nil
		}
		_, err4 := a.mikrotikGet("/api/system/identity")
		if err4 == nil {
			a.useREST = false
			log.Printf("[mikrotik:%s] Connected via HTTP /api/ path", profile.Name)
			return nil
		}
	}

	return fmt.Errorf("MikroTik verification failed (tried REST and /api/): %w", err)
}

func (a *MikroTikAdapter) Collect() (map[string]interface{}, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	prefix := a.apiPrefix()

	// ── System data ──
	identity, _ := a.mikrotikGet(prefix + "/system/identity")
	resource, _ := a.mikrotikGet(prefix + "/system/resource")
	routerboard, _ := a.mikrotikGet(prefix + "/system/routerboard")
	packages, _ := a.mikrotikGet(prefix + "/system/package")
	health, _ := a.mikrotikGet(prefix + "/system/health")

	// ── Interfaces ──
	interfaces, _ := a.mikrotikGet(prefix + "/interface")

	// ── Bridge ──
	bridges, _ := a.mikrotikGet(prefix + "/interface/bridge")
	bridgePorts, _ := a.mikrotikGet(prefix + "/interface/bridge/port")
	bridgeVlans, _ := a.mikrotikGet(prefix + "/interface/bridge/vlan")

	// ── IP ──
	ipAddresses, _ := a.mikrotikGet(prefix + "/ip/address")
	routes, _ := a.mikrotikGet(prefix + "/ip/route")

	// ── Firewall ──
	fwFilter, _ := a.mikrotikGet(prefix + "/ip/firewall/filter")
	fwNat, _ := a.mikrotikGet(prefix + "/ip/firewall/nat")

	// ── Services ──
	dhcpServers, _ := a.mikrotikGet(prefix + "/ip/dhcp-server")
	dnsConfig, _ := a.mikrotikGet(prefix + "/ip/dns")

	// ── Discovery ──
	neighbors, _ := a.mikrotikGet(prefix + "/ip/neighbor")

	// ── Wireless (optional — not present on all models) ──
	wirelessIfaces, _ := a.mikrotikGet(prefix + "/interface/wireless")
	wirelessClients, _ := a.mikrotikGet(prefix + "/interface/wireless/registration-table")

	// Build normalized snapshot
	snapshotData := a.normalizeSnapshot(
		identity, resource, routerboard, packages, health,
		interfaces, bridges, bridgePorts, bridgeVlans,
		ipAddresses, routes, fwFilter, fwNat,
		dhcpServers, dnsConfig, neighbors,
		wirelessIfaces, wirelessClients,
	)

	// Build alerts
	alerts := a.buildAlerts(snapshotData)

	// Extract signals for cloud rollup
	signals := extractMikroTikSignals(snapshotData)

	result := map[string]interface{}{
		"capabilities": a.Capabilities(),
		"snapshotData": snapshotData,
		"alerts":       alerts,
		"collectedAt":  now,
		"_signals":     signals,
	}

	if len(signals) > 0 {
		log.Printf("[mikrotik:%s] Emitting %d signals for cloud rollup", a.profile.Name, len(signals))
		for i, s := range signals {
			log.Printf("[mikrotik:%s]   signal[%d] key=%s sev=%s label=%s", a.profile.Name, i, s.Key, s.Severity, s.Label)
		}
	}

	return result, nil
}

func (a *MikroTikAdapter) apiPrefix() string {
	if a.useREST {
		return "/rest"
	}
	return "/api"
}

func (a *MikroTikAdapter) normalizeSnapshot(
	identity, resource, routerboard, packages, health,
	interfaces, bridges, bridgePorts, bridgeVlans,
	ipAddresses, routes, fwFilter, fwNat,
	dhcpServers, dnsConfig, neighbors,
	wirelessIfaces, wirelessClients interface{},
) map[string]interface{} {
	out := map[string]interface{}{}

	// ── Identity ──
	identityData := map[string]interface{}{}
	if m := mtikFirstOrSelf(identity); m != nil {
		identityData["name"] = mtikStr(m, "name")
		out["deviceName"] = mtikStr(m, "name")
	}
	out["identity"] = identityData

	// ── System ──
	systemData := map[string]interface{}{}
	if m := mtikFirstOrSelf(resource); m != nil {
		systemData["boardName"] = mtikStr(m, "board-name")
		systemData["architecture"] = mtikStr(m, "architecture-name")
		systemData["version"] = mtikStr(m, "version")
		systemData["uptime"] = mtikStr(m, "uptime")
		systemData["cpuCount"] = mtikStr(m, "cpu-count")
		systemData["cpuLoad"] = mtikStr(m, "cpu-load")
		systemData["freeMemory"] = mtikStr(m, "free-memory")
		systemData["totalMemory"] = mtikStr(m, "total-memory")
		systemData["freeHddSpace"] = mtikStr(m, "free-hdd-space")
		systemData["totalHddSpace"] = mtikStr(m, "total-hdd-space")
		systemData["platform"] = mtikStr(m, "platform")
		out["version"] = mtikStr(m, "version")
		out["boardName"] = mtikStr(m, "board-name")
		out["architecture"] = mtikStr(m, "architecture-name")
		out["cpuLoad"] = mtikStr(m, "cpu-load")
		out["uptime"] = mtikStr(m, "uptime")
	}
	if m := mtikFirstOrSelf(routerboard); m != nil {
		systemData["routerboard"] = mtikStr(m, "routerboard")
		systemData["model"] = mtikStr(m, "model")
		systemData["serialNumber"] = mtikStr(m, "serial-number")
		systemData["firmwareType"] = mtikStr(m, "firmware-type")
		systemData["currentFirmware"] = mtikStr(m, "current-firmware")
		systemData["upgradeFirmware"] = mtikStr(m, "upgrade-firmware")
		out["model"] = mtikStr(m, "model")
		out["serialNumber"] = mtikStr(m, "serial-number")
	}
	out["system"] = systemData

	// ── Packages ──
	pkgList := mtikToSlice(packages)
	pkgSummary := make([]map[string]interface{}, 0, len(pkgList))
	for _, p := range pkgList {
		pm, _ := p.(map[string]interface{})
		if pm == nil {
			continue
		}
		pkgSummary = append(pkgSummary, map[string]interface{}{
			"name":     mtikStr(pm, "name"),
			"version":  mtikStr(pm, "version"),
			"disabled": mtikStr(pm, "disabled"),
		})
	}
	out["packages"] = pkgSummary

	// ── Interfaces ──
	ifaceList := mtikToSlice(interfaces)
	ifaceSummary := make([]map[string]interface{}, 0, len(ifaceList))
	ifaceUp, ifaceDown, ifaceDisabled := 0, 0, 0
	for _, i := range ifaceList {
		im, _ := i.(map[string]interface{})
		if im == nil {
			continue
		}
		running := mtikStr(im, "running")
		disabled := mtikStr(im, "disabled")
		if disabled == "true" {
			ifaceDisabled++
		} else if running == "true" {
			ifaceUp++
		} else {
			ifaceDown++
		}
		entry := map[string]interface{}{
			"name":     mtikStr(im, "name"),
			"type":     mtikStr(im, "type"),
			"running":  running,
			"disabled": disabled,
			"macAddr":  mtikStr(im, "mac-address"),
			"mtu":      mtikStr(im, "mtu"),
			"rxBytes":  mtikStr(im, "rx-byte"),
			"txBytes":  mtikStr(im, "tx-byte"),
			"rxErrors": mtikStr(im, "rx-error"),
			"txErrors": mtikStr(im, "tx-error"),
		}
		ifaceSummary = append(ifaceSummary, entry)
	}
	out["interfaces"] = ifaceSummary
	out["interfaceCounts"] = map[string]interface{}{
		"total":    len(ifaceList),
		"up":       ifaceUp,
		"down":     ifaceDown,
		"disabled": ifaceDisabled,
	}

	// ── Bridge ──
	bridgeList := mtikToSlice(bridges)
	bridgePortList := mtikToSlice(bridgePorts)
	bridgeVlanList := mtikToSlice(bridgeVlans)
	bridging := map[string]interface{}{
		"bridges":    mtikFlattenList(bridgeList, []string{"name", "protocol-mode", "vlan-filtering", "admin-mac"}),
		"ports":      mtikFlattenList(bridgePortList, []string{"interface", "bridge", "pvid", "hw", "disabled"}),
		"vlans":      mtikFlattenList(bridgeVlanList, []string{"bridge", "vlan-ids", "tagged", "untagged"}),
		"bridgeCount": len(bridgeList),
		"portCount":   len(bridgePortList),
		"vlanCount":   len(bridgeVlanList),
	}
	out["bridging"] = bridging

	// ── Routing ──
	routeList := mtikToSlice(routes)
	routeSummary := mtikFlattenList(routeList, []string{"dst-address", "gateway", "distance", "routing-table", "scope", "pref-src"})
	out["routing"] = map[string]interface{}{
		"routes":     routeSummary,
		"routeCount": len(routeList),
	}

	// ── IP Addresses ──
	addrList := mtikToSlice(ipAddresses)
	out["ipAddresses"] = mtikFlattenList(addrList, []string{"address", "interface", "network", "disabled", "dynamic"})

	// ── Firewall ──
	filterList := mtikToSlice(fwFilter)
	natList := mtikToSlice(fwNat)
	out["firewall"] = map[string]interface{}{
		"filters":     mtikFlattenList(filterList, []string{"chain", "action", "src-address", "dst-address", "protocol", "dst-port", "comment", "disabled"}),
		"nat":         mtikFlattenList(natList, []string{"chain", "action", "src-address", "dst-address", "to-addresses", "to-ports", "protocol", "dst-port", "comment", "disabled"}),
		"filterCount": len(filterList),
		"natCount":    len(natList),
	}

	// ── Services ──
	dhcpList := mtikToSlice(dhcpServers)
	services := map[string]interface{}{
		"dhcpServers": mtikFlattenList(dhcpList, []string{"name", "interface", "address-pool", "disabled", "lease-count"}),
		"dhcpCount":   len(dhcpList),
	}
	if m := mtikFirstOrSelf(dnsConfig); m != nil {
		services["dns"] = map[string]interface{}{
			"servers":                mtikStr(m, "servers"),
			"allowRemoteRequests":    mtikStr(m, "allow-remote-requests"),
			"dynamicServers":         mtikStr(m, "dynamic-servers"),
			"cacheSize":             mtikStr(m, "cache-size"),
			"cacheUsed":             mtikStr(m, "cache-used"),
		}
	}
	out["services"] = services

	// ── Neighbors ──
	neighborList := mtikToSlice(neighbors)
	out["neighbors"] = mtikFlattenList(neighborList, []string{"identity", "address", "interface", "mac-address", "platform", "board", "version"})

	// ── Wireless (optional) ──
	wlIfaces := mtikToSlice(wirelessIfaces)
	wlClients := mtikToSlice(wirelessClients)
	wireless := map[string]interface{}{
		"interfaces": mtikFlattenList(wlIfaces, []string{"name", "ssid", "mode", "band", "channel-width", "frequency", "disabled", "running"}),
		"clients":    mtikFlattenList(wlClients, []string{"interface", "mac-address", "signal-strength", "tx-rate", "rx-rate", "uptime", "last-ip"}),
		"ifaceCount":  len(wlIfaces),
		"clientCount": len(wlClients),
	}
	out["wireless"] = wireless

	// ── Health (optional — not all models expose this) ──
	healthList := mtikToSlice(health)
	if len(healthList) > 0 {
		out["health"] = mtikFlattenList(healthList, []string{"name", "value", "type"})
	}

	// ── Capability profile (derived from collected data) ──
	caps := map[string]interface{}{
		"isRouter":   len(routeList) > 0,
		"isSwitch":   len(bridgeList) > 0 || len(bridgeVlanList) > 0,
		"isWireless": len(wlIfaces) > 0,
		"isVirtual":  isVirtualRouterOS(resource),
		"hasDhcp":    len(dhcpList) > 0,
		"hasNat":     len(natList) > 0,
		"hasVlans":   len(bridgeVlanList) > 0,
		"hasBridge":  len(bridgeList) > 0,
	}
	out["capabilities"] = caps

	// ── Raw data (for deep inspection) ──
	out["_raw"] = map[string]interface{}{
		"identity":         identity,
		"resource":         resource,
		"routerboard":      routerboard,
		"packages":         packages,
		"health":           health,
		"interfaces":       interfaces,
		"bridges":          bridges,
		"bridgePorts":      bridgePorts,
		"bridgeVlans":      bridgeVlans,
		"ipAddresses":      ipAddresses,
		"routes":           routes,
		"firewallFilter":   fwFilter,
		"firewallNat":      fwNat,
		"dhcpServers":      dhcpServers,
		"dnsConfig":        dnsConfig,
		"neighbors":        neighbors,
		"wirelessIfaces":   wirelessIfaces,
		"wirelessClients":  wirelessClients,
	}

	return out
}

func (a *MikroTikAdapter) buildAlerts(data map[string]interface{}) []map[string]interface{} {
	var alerts []map[string]interface{}

	if counts, ok := data["interfaceCounts"].(map[string]interface{}); ok {
		down := toInt(counts["down"])
		if down > 0 {
			alerts = append(alerts, map[string]interface{}{
				"severity": "warning",
				"source":   "mikrotik",
				"message":  fmt.Sprintf("%d interface(s) down", down),
			})
		}
	}

	return alerts
}

// extractMikroTikSignals produces signals for Hybrid Mode cloud rollup.
func extractMikroTikSignals(data map[string]interface{}) []SnapshotSignal {
	var sigs []SnapshotSignal

	// Interface health
	if counts, ok := data["interfaceCounts"].(map[string]interface{}); ok {
		down := toInt(counts["down"])
		if down > 0 {
			sev := "warning"
			if down > 3 {
				sev = "error"
			}
			sigs = append(sigs, SnapshotSignal{
				Key: "interface.down", Label: fmt.Sprintf("%d interface(s) down", down),
				Value: fmt.Sprintf("%d", down), Severity: sev,
			})
		}
		disabled := toInt(counts["disabled"])
		if disabled > 0 {
			sigs = append(sigs, SnapshotSignal{
				Key: "interface.disabled", Label: fmt.Sprintf("%d interface(s) disabled", disabled),
				Value: fmt.Sprintf("%d", disabled), Severity: "info",
			})
		}
	}

	// Firewall
	if fw, ok := data["firewall"].(map[string]interface{}); ok {
		if toInt(fw["filterCount"]) == 0 {
			sigs = append(sigs, SnapshotSignal{
				Key: "firewall.empty", Label: "No firewall filter rules configured",
				Value: "0", Severity: "warning",
			})
		}
	}

	// Bridge VLANs
	if br, ok := data["bridging"].(map[string]interface{}); ok {
		if toInt(br["vlanCount"]) > 0 {
			sigs = append(sigs, SnapshotSignal{
				Key: "bridge.vlans_active", Label: fmt.Sprintf("%d bridge VLAN(s) configured", toInt(br["vlanCount"])),
				Value: fmt.Sprintf("%d", toInt(br["vlanCount"])), Severity: "info",
			})
		}
	}

	// Version / firmware
	if sys, ok := data["system"].(map[string]interface{}); ok {
		current := mtikStr(sys, "currentFirmware")
		upgrade := mtikStr(sys, "upgradeFirmware")
		if current != "" && upgrade != "" && current != upgrade {
			sigs = append(sigs, SnapshotSignal{
				Key: "firmware.upgrade_available", Label: fmt.Sprintf("Firmware upgrade available: %s → %s", current, upgrade),
				Value: upgrade, Severity: "info",
			})
		}
	}

	// CPU load
	cpuLoad := mtikStr(data, "cpuLoad")
	if cpuLoad != "" {
		load := toInt(map[string]interface{}{"v": cpuLoad})
		if cpuN, err := fmt.Sscanf(cpuLoad, "%d", &load); cpuN == 1 && err == nil {
			if load > 90 {
				sigs = append(sigs, SnapshotSignal{
					Key: "cpu.high", Label: fmt.Sprintf("CPU load %d%%", load),
					Value: fmt.Sprintf("%d", load), Severity: "error",
				})
			} else if load > 70 {
				sigs = append(sigs, SnapshotSignal{
					Key: "cpu.elevated", Label: fmt.Sprintf("CPU load %d%%", load),
					Value: fmt.Sprintf("%d", load), Severity: "warning",
				})
			}
		}
	}

	// Wireless clients
	if wl, ok := data["wireless"].(map[string]interface{}); ok {
		clients := toInt(wl["clientCount"])
		if clients > 0 {
			sigs = append(sigs, SnapshotSignal{
				Key: "wireless.clients_active", Label: fmt.Sprintf("%d wireless client(s) connected", clients),
				Value: fmt.Sprintf("%d", clients), Severity: "info",
			})
		}
	}

	return sigs
}

func (a *MikroTikAdapter) Capabilities() []string {
	return []string{
		"mikrotik.read.system",
		"mikrotik.read.interfaces",
		"mikrotik.read.bridge",
		"mikrotik.read.routing",
		"mikrotik.read.firewall",
		"mikrotik.read.services",
		"mikrotik.read.neighbors",
		"mikrotik.read.wireless",
		"mikrotik.read.health",
	}
}

func (a *MikroTikAdapter) HealthCheck() error {
	_, err := a.mikrotikGet(a.apiPrefix() + "/system/identity")
	return err
}

func (a *MikroTikAdapter) Close() error {
	a.client = nil
	return nil
}

// ── HTTP helpers ─────────────────────────────────────────────────────

func (a *MikroTikAdapter) mikrotikGet(path string) (interface{}, error) {
	url := a.baseURL + path
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(a.user, a.pass)
	req.Header.Set("Accept", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("JSON decode failed: %w", err)
	}

	return result, nil
}

// ── Utility helpers ──────────────────────────────────────────────────

// mtikStr extracts a string value from a map by key(s), returning "" if missing.
func mtikStr(m interface{}, keys ...string) string {
	mm, ok := m.(map[string]interface{})
	if !ok {
		return ""
	}
	for _, k := range keys {
		if v, ok := mm[k]; ok {
			switch vv := v.(type) {
			case string:
				return vv
			case float64:
				if vv == float64(int64(vv)) {
					return fmt.Sprintf("%d", int64(vv))
				}
				return fmt.Sprintf("%g", vv)
			case bool:
				if vv {
					return "true"
				}
				return "false"
			}
		}
	}
	return ""
}

// mtikFirstOrSelf returns the first element of a slice, or the map itself.
func mtikFirstOrSelf(v interface{}) map[string]interface{} {
	if v == nil {
		return nil
	}
	if arr, ok := v.([]interface{}); ok {
		if len(arr) == 0 {
			return nil
		}
		if m, ok := arr[0].(map[string]interface{}); ok {
			return m
		}
		return nil
	}
	if m, ok := v.(map[string]interface{}); ok {
		return m
	}
	return nil
}

// mtikToSlice normalizes a response to a slice (RouterOS REST returns arrays).
func mtikToSlice(v interface{}) []interface{} {
	if v == nil {
		return nil
	}
	if arr, ok := v.([]interface{}); ok {
		return arr
	}
	if m, ok := v.(map[string]interface{}); ok {
		return []interface{}{m}
	}
	return nil
}

// mtikFlattenList extracts specified keys from a slice of maps into flat maps.
func mtikFlattenList(items []interface{}, keys []string) []map[string]interface{} {
	result := make([]map[string]interface{}, 0, len(items))
	for _, item := range items {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		flat := map[string]interface{}{}
		for _, k := range keys {
			if v, ok := m[k]; ok {
				flat[k] = v
			}
		}
		if len(flat) > 0 {
			result = append(result, flat)
		}
	}
	return result
}

// isVirtualRouterOS checks if the device is a CHR or virtual instance.
func isVirtualRouterOS(resource interface{}) bool {
	m := mtikFirstOrSelf(resource)
	if m == nil {
		return false
	}
	platform := strings.ToLower(mtikStr(m, "platform"))
	boardName := strings.ToLower(mtikStr(m, "board-name"))
	return strings.Contains(platform, "chr") ||
		strings.Contains(boardName, "chr") ||
		strings.Contains(platform, "virtual") ||
		strings.Contains(boardName, "virtual") ||
		strings.Contains(platform, "kvm") ||
		strings.Contains(platform, "vmware") ||
		strings.Contains(platform, "xen") ||
		strings.Contains(platform, "hyper-v")
}
