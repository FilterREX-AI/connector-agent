// ForgeAI Connector Host — Brocade FC Adapter (read-only)
//
// Collects switch chassis info, port status, media (SFP) diagnostics,
// and zoning configuration from Brocade FOS 8.2+ switches via the
// /rest/running/ REST API.

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"strings"
	"time"
)

type BrocadeAdapter struct {
	profile *TargetProfile
	client  *http.Client
	baseURL string
	user    string
	pass    string
	token   string
}

func NewBrocadeAdapter(profile *TargetProfile) (TargetAdapter, error) {
	return &BrocadeAdapter{profile: profile}, nil
}

func (a *BrocadeAdapter) Init(profile *TargetProfile, creds map[string]string) error {
	a.profile = profile
	a.baseURL = profile.Endpoint

	timeout := 15 * time.Second
	if profile.ResourceLimits.TimeoutSecs > 0 {
		timeout = time.Duration(profile.ResourceLimits.TimeoutSecs) * time.Second
	}
	if timeout > 30*time.Second {
		timeout = 30 * time.Second
	}
	a.client = NewHTTPClientFromProfile(profile, timeout)

	a.user = creds["username"]
	a.pass = creds["password"]
	if t := creds["token"]; t != "" {
		a.token = t
	} else if t := creds["api_token"]; t != "" {
		a.token = t
	}

	log.Printf("[brocade:%s] Verifying FOS REST API at %s...", profile.Name, a.baseURL)
	_, err := a.brocadeGet("/rest/running/brocade-chassis/chassis")
	if err != nil {
		// If HTTPS fails with connection refused, try HTTP fallback
		if strings.HasPrefix(a.baseURL, "https://") && isConnRefused(err) {
			httpURL := "http://" + strings.TrimPrefix(a.baseURL, "https://")
			log.Printf("[brocade:%s] HTTPS connection refused, trying HTTP fallback at %s...", profile.Name, httpURL)
			a.baseURL = httpURL
			_, err2 := a.brocadeGet("/rest/running/brocade-chassis/chassis")
			if err2 != nil {
				return fmt.Errorf("Brocade FOS REST verification failed (tried HTTPS and HTTP): %w", err2)
			}
			log.Printf("[brocade:%s] Connected via HTTP (no TLS)", profile.Name)
			return nil
		}
		return fmt.Errorf("Brocade FOS REST verification failed: %w", err)
	}
	log.Printf("[brocade:%s] Connected via HTTPS", profile.Name)
	return nil
}

func (a *BrocadeAdapter) Collect() (map[string]interface{}, error) {
	now := time.Now().UTC().Format(time.RFC3339)

	chassis, _ := a.brocadeGet("/rest/running/brocade-chassis/chassis")
	switchInfo, _ := a.brocadeGet("/rest/running/brocade-fibrechannel-switch/fibrechannel-switch")
	ports, _ := a.brocadeGet("/rest/running/brocade-interface/fibrechannel")
	media, _ := a.brocadeGet("/rest/running/brocade-media/media-rdp")
	zoneConfig, _ := a.brocadeGet("/rest/running/brocade-zone/effective-configuration")
	definedConfig, _ := a.brocadeGet("/rest/running/brocade-zone/defined-configuration")
	fabricInfo, _ := a.brocadeGet("/rest/running/brocade-fabric/fabric-switch")
	// FRU: always try blade + power-supply first — /fru on many FOS versions
	// returns blades only, silently dropping PSU data.
	bladeFru, _ := a.brocadeGet("/rest/running/brocade-fru/blade")
	psFru, _ := a.brocadeGet("/rest/running/brocade-fru/power-supply")
	fru := mergeBrocadeFru(bladeFru, psFru)
	if fru == nil {
		// Fallback: older FOS single endpoint
		fru, _ = a.brocadeGet("/rest/running/brocade-fru/fru")
	}

	snapshotData := normalizeBrocadeSnapshot(chassis, switchInfo, ports, media, zoneConfig, definedConfig, fabricInfo, fru)

	// Build alerts from normalized data
	var alerts []map[string]interface{}
	if pf, _ := snapshotData["portsFaulty"].(int); pf > 0 {
		alerts = append(alerts, map[string]interface{}{
			"severity": "critical",
			"source":   "brocade",
			"message":  fmt.Sprintf("%d port(s) in faulty state", pf),
		})
	}
	if raw, ok := snapshotData["_raw"].(map[string]interface{}); ok {
		if fruRaw, ok := raw["fru"].(map[string]interface{}); ok {
			fruItems := brocadeExtractFruItems(fruRaw)
			psuCount := 0
			failedPsus := 0
			for _, item := range fruItems {
				fm, _ := item.(map[string]interface{})
				if fm == nil {
					continue
				}
				name := strings.ToUpper(brocadeStr(fm, "name"))
				if strings.Contains(name, "PS") || strings.Contains(name, "POWER") {
					psuCount++
					if brocadeFruStateFailed(strings.ToLower(strings.TrimSpace(brocadeStr(fm, "operational-state")))) {
						failedPsus++
					}
				}
			}
			if failedPsus > 0 {
				alerts = append(alerts, map[string]interface{}{
					"severity": "critical",
					"source":   "brocade",
					"message":  fmt.Sprintf("%d PSU(s) not operational", failedPsus),
				})
			} else if psuCount == 1 {
				alerts = append(alerts, map[string]interface{}{
					"severity": "warning",
					"source":   "brocade",
					"message":  "Single PSU detected — no power redundancy",
				})
			}
		}
	}

	result := map[string]interface{}{
		"capabilities": a.Capabilities(),
		"snapshotData": snapshotData,
		"alerts":       alerts,
		"collectedAt":  now,
		"_signals":     extractBrocadeSignals(snapshotData),
	}
	if sigs, ok := result["_signals"].([]SnapshotSignal); ok {
		log.Printf("[brocade:%s] Emitting %d signals for cloud rollup", a.profile.Name, len(sigs))
		for i, s := range sigs {
			log.Printf("[brocade:%s]   signal[%d] key=%s sev=%s label=%s", a.profile.Name, i, s.Key, s.Severity, s.Label)
		}
	}
	return result, nil
}

// extractBrocadeSignals mirrors frontend signal rules for Hybrid Mode rollup.
func extractBrocadeSignals(data map[string]interface{}) []SnapshotSignal {
	var sigs []SnapshotSignal

	switchState, hasSwitch := data["switchState"].(string)
	if !hasSwitch || switchState == "" {
		// switchState absent — the switch-info API didn't return switch-state field.
		// Treat as unknown, not healthy, so signal rollup always has something.
		sigs = append(sigs, SnapshotSignal{
			Key: "switch.unknown", Label: "Switch state not reported",
			Value: "unknown", Severity: "warning",
		})
	} else if !strings.EqualFold(switchState, "online") {
		sigs = append(sigs, SnapshotSignal{
			Key: "switch.unhealthy", Label: fmt.Sprintf("Switch state: %s", switchState),
			Value: switchState, Severity: "error",
		})
	}

	var ePortCount int
	if ports, ok := data["ports"].(map[string]interface{}); ok {
		disabled := toInt(ports["disabled"])
		if disabled > 0 {
			sigs = append(sigs, SnapshotSignal{
				Key: "port.disabled", Label: fmt.Sprintf("%d port(s) disabled", disabled),
				Value: fmt.Sprintf("%d", disabled), Severity: "warning",
			})
		}
		errPorts := toInt(ports["withErrors"])
		if errPorts == 0 {
			errPorts = toInt(ports["faulty"])
		}
		if errPorts == 0 {
			errPorts = toInt(data["portsFaulty"])
		}
		if errPorts > 0 {
			sev := "warning"
			if errPorts > 3 {
				sev = "error"
			}
			sigs = append(sigs, SnapshotSignal{
				Key: "port.errors", Label: fmt.Sprintf("%d port(s) with errors", errPorts),
				Value: fmt.Sprintf("%d", errPorts), Severity: sev,
			})
		}
		ePortCount = toInt(ports["ePort"])
	}

	detailedSfpSignals := 0
	if raw, ok := data["_raw"].(map[string]interface{}); ok {
		portStates := map[string]int{}
		if portsRaw, ok := raw["ports"].(map[string]interface{}); ok {
			for _, p := range brocadeExtractArray(portsRaw, "fibrechannel") {
				pm, _ := p.(map[string]interface{})
				if pm == nil {
					continue
				}
				name := brocadeStr(pm, "name")
				if name != "" {
					portStates[name] = int(brocadeNum(pm, "operational-status"))
				}
			}
		}

		if mediaRaw, ok := raw["media"].(map[string]interface{}); ok {
			for _, m := range brocadeExtractArray(mediaRaw, "media-rdp") {
				mm, _ := m.(map[string]interface{})
				if mm == nil {
					continue
				}
				port := brocadeStr(mm, "name")
				linkState := "unknown"
				if st, ok := portStates[port]; ok {
					if st == 2 {
						linkState = "up"
					} else {
						linkState = "down"
					}
				}
				status, reasons := classifyBrocadeMedia(mm, linkState)
				if status == "alarm" {
					detailedSfpSignals++
					sigs = append(sigs, SnapshotSignal{
						Key: "sfp.alarm",
						Label: fmt.Sprintf("SFP %s: %s", port, strings.Join(reasons, ", ")),
						Entity: port,
						Severity: "critical",
					})
				} else if status == "warning" {
					detailedSfpSignals++
					sigs = append(sigs, SnapshotSignal{
						Key: "sfp.out_of_range",
						Label: fmt.Sprintf("SFP %s: %s", port, strings.Join(reasons, ", ")),
						Entity: port,
						Severity: "warning",
					})
				}
			}
		}

		if fruRaw, ok := raw["fru"].(map[string]interface{}); ok {
			fruItems := brocadeExtractFruItems(fruRaw)
			psuCount := 0
			failedPsus := 0
			failedFans := 0
			for _, item := range fruItems {
				fm, _ := item.(map[string]interface{})
				if fm == nil {
					continue
				}
				name := strings.ToUpper(brocadeStr(fm, "name"))
				state := strings.ToLower(strings.TrimSpace(brocadeStr(fm, "operational-state")))
				switch {
				case strings.Contains(name, "PS") || strings.Contains(name, "POWER"):
					psuCount++
					if brocadeFruStateFailed(state) {
						failedPsus++
					}
				case strings.Contains(name, "FAN"):
					if brocadeFruStateFailed(state) {
						failedFans++
					}
				}
			}
			if failedPsus > 0 {
				sigs = append(sigs, SnapshotSignal{
					Key: "hardware.psu.failed",
					Label: fmt.Sprintf("%d PSU(s) not operational", failedPsus),
					Value: fmt.Sprintf("%d", failedPsus),
					Severity: "critical",
				})
			} else if psuCount == 1 {
				sigs = append(sigs, SnapshotSignal{
					Key: "hardware.psu.missing",
					Label: "Single PSU — no power redundancy",
					Value: "1",
					Severity: "warning",
				})
			}
			if failedFans > 0 {
				sigs = append(sigs, SnapshotSignal{
					Key: "hardware.fan.failed",
					Label: fmt.Sprintf("%d fan(s) not operational", failedFans),
					Value: fmt.Sprintf("%d", failedFans),
					Severity: "critical",
				})
			}
		}
	}

	if detailedSfpSignals == 0 {
		sfpWarn := toInt(data["sfpWarnings"])
		if sfpWarn > 0 {
			sigs = append(sigs, SnapshotSignal{
				Key: "sfp.warning", Label: fmt.Sprintf("%d SFP warning(s)", sfpWarn),
				Value: fmt.Sprintf("%d", sfpWarn), Severity: "warning",
			})
		}
	}

	if activeCfg, _ := data["zoningActiveCfg"].(string); strings.TrimSpace(activeCfg) == "" {
		sigs = append(sigs, SnapshotSignal{
			Key: "zoning.no_active_cfg", Label: "No active zone configuration",
			Value: "true", Severity: "warning",
		})
	}

	if ePortCount > 0 && toInt(data["fabricSwitchCount"]) == 0 {
		if switchState, _ := data["switchState"].(string); strings.EqualFold(switchState, "online") {
			sigs = append(sigs, SnapshotSignal{
				Key: "fabric.segmented", Label: "Fabric segmentation detected",
				Value: "true", Severity: "error",
			})
		}
	}

	return sigs
}

func (a *BrocadeAdapter) Capabilities() []string {
	return []string{
		"brocade.read.health",
		"brocade.read.chassis",
		"brocade.read.ports",
		"brocade.read.media",
		"brocade.read.zoning",
		"brocade.read.fabric",
		"brocade.read.fru",
	}
}

func (a *BrocadeAdapter) HealthCheck() error {
	_, err := a.brocadeGet("/rest/running/brocade-chassis/chassis")
	return err
}

func (a *BrocadeAdapter) Close() error {
	a.client = nil
	return nil
}

// ── Normalization ──────────────────────────────────────────────────────

// normalizeBrocadeSnapshot flattens raw FOS REST responses into
// dashboard-ready fields expected by the frontend hook.
func normalizeBrocadeSnapshot(
	chassis, switchInfo, ports, media, zoneConfig, definedConfig, fabricInfo, fru map[string]interface{},
) map[string]interface{} {
	out := map[string]interface{}{}

	// ── Switch identity ──
	if sw := brocadeExtractFirst(switchInfo, "fibrechannel-switch"); sw != nil {
		if v := brocadeStr(sw, "name", "switch-name", "user-friendly-name"); v != "" {
			out["switchName"] = v
		}
		if v := brocadeStr(sw, "switch-wwn", "wwn"); v != "" {
			out["switchWwn"] = v
		}
		// switch-role: numeric enum 0=subordinate,1=disabled,2=principal; also accept string
		if roleNum := brocadeNum(sw, "switch-role"); roleNum > 0 || brocadeStr(sw, "switch-role") != "" {
			switch int(roleNum) {
			case 0:
				out["switchRole"] = "Subordinate"
			case 1:
				out["switchRole"] = "Disabled"
			case 2:
				out["switchRole"] = "Principal"
			default:
				if sv := brocadeStr(sw, "switch-role"); sv != "" {
					out["switchRole"] = sv
				} else {
					out["switchRole"] = fmt.Sprintf("role-%d", int(roleNum))
				}
			}
		}
		out["domainId"] = brocadeNum(sw, "domain-id")
		if v := brocadeStr(sw, "firmware-version", "firmware-Version", "fw-version"); v != "" {
			out["firmwareVersion"] = v
		}
		// model: fibrechannel-switch may return a numeric product ID (e.g. 109.1);
		// prefer chassis product-name, so only use this as a last resort
		if v := brocadeStr(sw, "model"); v != "" {
			out["_switchModelRaw"] = v
		}
		// switch-state: 0=undefined,1=offline,2=online,3=testing,4=faulty; also accept string
		if _, hasState := sw["switch-state"]; hasState {
			st := brocadeNum(sw, "switch-state")
			switch int(st) {
			case 2:
				out["switchState"] = "Online"
			case 1:
				out["switchState"] = "Offline"
			case 3:
				out["switchState"] = "Testing"
			case 4:
				out["switchState"] = "Faulty"
			default:
				if sv := brocadeStr(sw, "switch-state"); sv != "" && sv != "0" {
					out["switchState"] = sv
				} else {
					out["switchState"] = "Unknown"
				}
			}
		}
	}

	// ── Chassis info ──
	if ch := brocadeExtractFirst(chassis, "chassis"); ch != nil {
		// Always prefer chassis product-name for human-readable model
		if v := brocadeStr(ch, "product-name"); v != "" {
			out["model"] = v
		}
		// Fallback to switch-level model only if chassis didn't provide one
		if out["model"] == nil || out["model"] == "" {
			if raw, ok := out["_switchModelRaw"]; ok {
				out["model"] = raw
			}
		}
		if v := brocadeStr(ch, "serial-number"); v != "" {
			out["serialNumber"] = v
		}
		out["chassisName"] = ch["chassis-user-friendly-name"]
		out["productName"] = ch["product-name"]
	}

	// ── Port summary ──
	portItems := brocadeExtractArray(ports, "fibrechannel")
	portsOnline, portsOffline, portsFaulty, portsDisabled := 0, 0, 0, 0
	fPort, ePort := 0, 0
	licensedPorts := 0
	for _, p := range portItems {
		pm, _ := p.(map[string]interface{})
		if pm == nil {
			continue
		}
		opSt := brocadeNum(pm, "operational-status")
		switch int(opSt) {
		case 2:
			portsOnline++
		case 3:
			portsOffline++
		case 5:
			portsFaulty++
		default:
			portsOffline++
		}
		// is-enabled-state: 2=enabled (licensed), 6=disabled
		en := brocadeNum(pm, "is-enabled-state")
		if int(en) == 6 {
			portsDisabled++
		} else if int(en) == 2 || en == 1 {
			licensedPorts++
		}
		// port-type: 7=E-Port, 10/17=F-Port
		pt := brocadeNum(pm, "port-type")
		switch int(pt) {
		case 7:
			ePort++
		case 10, 17:
			fPort++
		}
	}

	// Count SFPs inserted from media endpoint
	mediaItems := brocadeExtractArray(media, "media-rdp")
	sfpInserted := len(mediaItems)

	out["ports"] = map[string]interface{}{
		"total":       len(portItems),
		"online":      portsOnline,
		"offline":     portsOffline,
		"faulty":      portsFaulty,
		"disabled":    portsDisabled,
		"withErrors":  portsFaulty,
		"fPort":       fPort,
		"ePort":       ePort,
		"licensed":    licensedPorts,
		"sfpInserted": sfpInserted,
	}
	// Top-level convenience fields for signal rules
	out["portTotal"] = len(portItems)
	out["portsOnline"] = portsOnline
	out["portsOffline"] = portsOffline
	out["portsFaulty"] = portsFaulty

	// ── SFP / Media warnings ──
	sfpWarnings := 0
	for _, m := range mediaItems {
		mm, _ := m.(map[string]interface{})
		if mm == nil {
			continue
		}
		// Check for power/temp alarm flags
		if hasBrocadeMediaWarning(mm) {
			sfpWarnings++
		}
	}
	out["sfpWarnings"] = sfpWarnings

	// ── Fabric ──
	fabricSwitches := brocadeExtractArray(fabricInfo, "fabric-switch")
	out["fabricSwitchCount"] = len(fabricSwitches)

	// ── Zoning (defined) — extract first so we can cross-reference ──
	var definedZones []interface{}
	var definedCfgs []interface{}
	var definedAliases []interface{}
	if dc := brocadeExtractFirst(definedConfig, "defined-configuration"); dc != nil {
		definedZones = normalizeToSlice(dc["zone"])
		definedAliases = normalizeToSlice(dc["alias"])
		definedCfgs = normalizeToSlice(dc["cfg"])
	}
	out["definedZoneCount"] = len(definedZones)
	out["definedAliasCount"] = len(definedAliases)
	out["definedCfgCount"] = len(definedCfgs)

	// ── Zoning (effective) — cross-reference against defined if zone list missing ──
	activeCfgName := ""
	effectiveZoneCount := 0
	var effectiveZoneNames []interface{}
	effectiveZoneCountResolved := false

	if ec := brocadeExtractFirst(zoneConfig, "effective-configuration"); ec != nil {
		if cfgName, ok := ec["cfg-name"].(string); ok {
			activeCfgName = cfgName
		}
		explicitZones := normalizeToSlice(ec["zone"])
		if len(explicitZones) > 0 {
			// FOS included the zone list directly — use it
			effectiveZoneCount = len(explicitZones)
			effectiveZoneCountResolved = true
		} else if activeCfgName != "" {
			// Cross-reference: find matching cfg in defined config
			for _, cfgRaw := range definedCfgs {
				cfgMap, _ := cfgRaw.(map[string]interface{})
				if cfgMap == nil {
					continue
				}
				if cfgMap["cfg-name"] == activeCfgName {
					memberZone, _ := cfgMap["member-zone"].(map[string]interface{})
					if memberZone != nil {
						effectiveZoneNames = normalizeToSlice(memberZone["zone-name"])
						effectiveZoneCount = len(effectiveZoneNames)
					}
					effectiveZoneCountResolved = true
					break
				}
			}
		}
	}

	out["activeCfgName"] = activeCfgName
	out["effectiveZoneCount"] = effectiveZoneCount
	out["effectiveZoneNames"] = effectiveZoneNames
	out["effectiveZoneCountResolved"] = effectiveZoneCountResolved
	// Legacy alias
	out["zoningActiveCfg"] = activeCfgName

	// ── Raw data for investigation drill-down ──
	out["_raw"] = map[string]interface{}{
		"chassis":       chassis,
		"switchInfo":    switchInfo,
		"ports":         ports,
		"media":         media,
		"zoneConfig":    zoneConfig,
		"definedConfig": definedConfig,
		"fabric":        fabricInfo,
		"fru":           fru,
	}

	return out
}

// hasBrocadeMediaWarning checks if a media-rdp entry has any warning/alarm flags set.
func hasBrocadeMediaWarning(m map[string]interface{}) bool {
	alarmKeys := []string{
		"remote-media-tx-power-alert-type",
		"remote-media-rx-power-alert-type",
		"remote-media-temperature-alert-type",
	}
	for _, k := range alarmKeys {
		if v, ok := m[k].(float64); ok && v != 0 {
			return true
		}
	}
	return false
}

func classifyBrocadeMedia(m map[string]interface{}, linkState string) (string, []string) {
	rxPower, rxOk := parseBrocadePowerDbm(m["rx-power"])
	txPower, txOk := parseBrocadePowerDbm(m["tx-power"])
	tempC, tempOk := parseBrocadeTemperatureC(m["temperature"])

	rxStatus, rxReason := brocadeClassifyMetric(rxPower, rxOk, -14, 3, -17, 5, "RX power")
	if linkState != "up" && rxOk && rxStatus != "ok" && rxPower < 3 {
		rxStatus, rxReason = "ok", ""
	}
	txStatus, txReason := brocadeClassifyMetric(txPower, txOk, -8, 1, -10, 3, "TX power")
	tempStatus, tempReason := brocadeClassifyMetric(tempC, tempOk, 0, 70, -5, 80, "Temperature")

	overall := "ok"
	if rxStatus == "alarm" || txStatus == "alarm" || tempStatus == "alarm" {
		overall = "alarm"
	} else if rxStatus == "warning" || txStatus == "warning" || tempStatus == "warning" {
		overall = "warning"
	}

	var reasons []string
	for _, reason := range []string{rxReason, txReason, tempReason} {
		if reason != "" {
			reasons = append(reasons, reason)
		}
	}
	return overall, reasons
}

func brocadeClassifyMetric(value float64, ok bool, warnLow, warnHigh, alarmLow, alarmHigh float64, label string) (string, string) {
	if !ok {
		return "ok", ""
	}
	if value < alarmLow {
		return "alarm", fmt.Sprintf("%s critically low (%.1f)", label, value)
	}
	if value > alarmHigh {
		return "alarm", fmt.Sprintf("%s critically high (%.1f)", label, value)
	}
	if value < warnLow {
		return "warning", fmt.Sprintf("%s low (%.1f)", label, value)
	}
	if value > warnHigh {
		return "warning", fmt.Sprintf("%s high (%.1f)", label, value)
	}
	return "ok", ""
}

func parseBrocadePowerDbm(v interface{}) (float64, bool) {
	s := strings.TrimSpace(brocadeStringValue(v))
	if s == "" || s == "—" || strings.EqualFold(s, "n/a") {
		return 0, false
	}
	lower := strings.ToLower(s)
	if strings.HasSuffix(lower, "dbm") {
		var n float64
		if _, err := fmt.Sscanf(s, "%f", &n); err == nil {
			return n, true
		}
		return 0, false
	}
	if strings.HasSuffix(lower, "mw") {
		var n float64
		if _, err := fmt.Sscanf(s, "%f", &n); err == nil && n > 0 {
			return 10 * math.Log10(n), true
		}
		return 0, false
	}
	if strings.HasSuffix(lower, "uw") || strings.HasSuffix(lower, "µw") {
		normalized := strings.ReplaceAll(lower, "µw", "uw")
		var n float64
		if _, err := fmt.Sscanf(normalized, "%f", &n); err == nil && n > 0 {
			return 10 * math.Log10(n/1000), true
		}
		return 0, false
	}
	var n float64
	if _, err := fmt.Sscanf(s, "%f", &n); err == nil && n > 0 {
		return 10 * math.Log10(n/1000), true
	}
	return 0, false
}

func parseBrocadeTemperatureC(v interface{}) (float64, bool) {
	s := strings.TrimSpace(brocadeStringValue(v))
	if s == "" || s == "—" || strings.EqualFold(s, "n/a") {
		return 0, false
	}
	var n float64
	if _, err := fmt.Sscanf(s, "%f", &n); err == nil {
		return n, true
	}
	return 0, false
}

func brocadeStringValue(v interface{}) string {
	switch tv := v.(type) {
	case string:
		return tv
	case float64:
		return fmt.Sprintf("%v", tv)
	case int:
		return fmt.Sprintf("%d", tv)
	case int64:
		return fmt.Sprintf("%d", tv)
	default:
		return ""
	}
}

func brocadeFruStateFailed(state string) bool {
	state = strings.ToLower(strings.TrimSpace(state))
	return state != "" && state != "enabled" && state != "ok" && state != "online"
}

// ── HTTP helpers ───────────────────────────────────────────────────────

func (a *BrocadeAdapter) brocadeGet(path string) (map[string]interface{}, error) {
	req, err := http.NewRequest("GET", a.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	if a.token != "" {
		req.Header.Set("Authorization", "Bearer "+a.token)
	} else if a.user != "" && a.pass != "" {
		req.SetBasicAuth(a.user, a.pass)
	}
	req.Header.Set("Accept", "application/yang-data+json")

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body[:min(200, len(body))]))
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// normalizeToSlice converts a value that may be a single object, an array,
// or nil into a consistent []interface{}. Use throughout the Brocade adapter
// to handle FOS responses that return single objects vs arrays.
func normalizeToSlice(v interface{}) []interface{} {
	if v == nil {
		return nil
	}
	if arr, ok := v.([]interface{}); ok {
		return arr
	}
	// Single object → wrap
	return []interface{}{v}
}

// brocadeExtractArray extracts an array from Brocade's nested Response envelope.
func brocadeExtractArray(resp map[string]interface{}, key string) []interface{} {
	if resp == nil {
		return nil
	}
	if arr, ok := resp[key].([]interface{}); ok {
		return arr
	}
	if obj, ok := resp[key].(map[string]interface{}); ok {
		return []interface{}{obj}
	}
	if r, ok := resp["Response"].(map[string]interface{}); ok {
		if arr, ok := r[key].([]interface{}); ok {
			return arr
		}
		if obj, ok := r[key].(map[string]interface{}); ok {
			return []interface{}{obj}
		}
	}
	return nil
}

// brocadeExtractFirst extracts a single object from Brocade's nested Response envelope.
// Handles both direct object and single-element array forms (FOS version variance).
func brocadeExtractFirst(resp map[string]interface{}, key string) map[string]interface{} {
	if resp == nil {
		return nil
	}
	// Direct object
	if obj, ok := resp[key].(map[string]interface{}); ok {
		return obj
	}
	// Array form — unwrap first element
	if arr, ok := resp[key].([]interface{}); ok && len(arr) > 0 {
		if obj, ok := arr[0].(map[string]interface{}); ok {
			return obj
		}
	}
	// Nested under Response
	if r, ok := resp["Response"].(map[string]interface{}); ok {
		if obj, ok := r[key].(map[string]interface{}); ok {
			return obj
		}
		if arr, ok := r[key].([]interface{}); ok && len(arr) > 0 {
			if obj, ok := arr[0].(map[string]interface{}); ok {
				return obj
			}
		}
	}
	return nil
}

// brocadeStr extracts a string value trying multiple key variants.
func brocadeStr(m map[string]interface{}, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			switch tv := v.(type) {
			case string:
				return tv
			case float64:
				return fmt.Sprintf("%v", tv)
			}
		}
	}
	return ""
}

// brocadeNum extracts a numeric value from various types (float64, bool, string).
func brocadeNum(m map[string]interface{}, keys ...string) float64 {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			switch tv := v.(type) {
			case float64:
				return tv
			case bool:
				if tv {
					return 1
				}
				return 0
			case string:
				// Try numeric parse
				var f float64
				if _, err := fmt.Sscanf(tv, "%f", &f); err == nil {
					return f
				}
			}
		}
	}
	return 0
}

// isConnRefused checks if an error is a TCP connection refused.
func isConnRefused(err error) bool {
	if err == nil {
		return false
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return opErr.Op == "dial" && strings.Contains(opErr.Err.Error(), "connection refused")
	}
	return strings.Contains(err.Error(), "connection refused")
}

// toInt extracts an int from an interface{} that may be int, float64, or int64.
func toInt(v interface{}) int {
	switch n := v.(type) {
	case int:
		return n
	case float64:
		return int(n)
	case int64:
		return int(n)
	}
	return 0
}

// mergeBrocadeFru combines results from /blade and /power-supply endpoints
// into a single {"fru": [...all items...]} structure.
func mergeBrocadeFru(blade, ps map[string]interface{}) map[string]interface{} {
	if blade == nil && ps == nil {
		return nil
	}
	var all []interface{}
	if blade != nil {
		for _, key := range []string{"blade", "fru"} {
			if items := brocadeExtractArray(blade, key); len(items) > 0 {
				all = append(all, items...)
				break
			}
		}
	}
	if ps != nil {
		for _, key := range []string{"power-supply", "fru"} {
			if items := brocadeExtractArray(ps, key); len(items) > 0 {
				all = append(all, items...)
				break
			}
		}
	}
	if len(all) == 0 {
		return nil
	}
	return map[string]interface{}{"Response": map[string]interface{}{"fru": all}}
}

// brocadeExtractFruItems tries all known FRU keys in order.
func brocadeExtractFruItems(fruRaw map[string]interface{}) []interface{} {
	for _, key := range []string{"fru", "blade", "power-supply"} {
		if items := brocadeExtractArray(fruRaw, key); len(items) > 0 {
			return items
		}
	}
	return nil
}
