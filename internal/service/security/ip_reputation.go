package security

import (
	"bufio"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type IPReputation struct {
	torList          map[string]bool
	datacenterRanges []*net.IPNet
	vpnRanges        []*net.IPNet
	proxyRanges      []*net.IPNet
	mu               sync.RWMutex
	lastUpdated      time.Time
}

type IPInfo struct {
	IP           string    `json:"ip"`
	IsTOR        bool      `json:"is_tor"`
	IsVPN        bool      `json:"is_vpn"`
	IsProxy      bool      `json:"is_proxy"`
	IsDataCenter bool      `json:"is_datacenter"`
	CountryCode  string    `json:"country_code"`
	ASN          string    `json:"asn"`
	RiskScore    int       `json:"risk_score"`
	LastUpdated  time.Time `json:"last_updated"`
}

func NewIPReputation() *IPReputation {
	ipRep := &IPReputation{
		torList:     make(map[string]bool),
		lastUpdated: time.Now(),
	}
	ipRep.initializeDatacenterRanges()
	go ipRep.loadTORNodes()
	go ipRep.loadVPNProxyLists()
	return ipRep
}

func (r *IPReputation) initializeDatacenterRanges() {
	datacenterCIDRs := []string{
		// AWS
		"3.0.0.0/9", "3.128.0.0/10", "3.192.0.0/11", "3.224.0.0/12",
		"52.0.0.0/10", "52.64.0.0/12", "52.80.0.0/13",
		// Google Cloud
		"8.34.0.0/17", "8.35.0.0/17", "23.236.48.0/20", "23.251.128.0/19",
		"34.0.0.0/11", "35.184.0.0/13",
		// Azure
		"13.64.0.0/11", "13.96.0.0/13", "20.0.0.0/10", "23.96.0.0/13",
		"40.64.0.0/10", "52.160.0.0/11",
		// DigitalOcean
		"138.68.0.0/17", "159.65.0.0/16", "167.99.0.0/16",
		// Other cloud providers
		"162.243.0.0/16", "104.236.0.0/16", "107.170.0.0/16",
	}

	for _, cidr := range datacenterCIDRs {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err == nil {
			r.datacenterRanges = append(r.datacenterRanges, ipnet)
		}
	}
}

func (r *IPReputation) loadTORNodes() {
	r.mu.Lock()
	defer r.mu.Unlock()

	urls := []string{
		"https://check.torproject.org/exit-addresses",
		"https://raw.githubusercontent.com/SecOps-Institute/Tor-IP-Addresses/master/tor-exit-nodes.lst",
	}

	for _, url := range urls {
		resp, err := http.Get(url)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(line, "ExitAddress") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					ip := parts[1]
					r.torList[ip] = true
				}
			} else if net.ParseIP(line) != nil {
				r.torList[line] = true
			}
		}

		if len(r.torList) > 0 {
			break
		}
	}

	// Fallback known TOR nodes
	if len(r.torList) == 0 {
		knownTORs := []string{
			"185.220.101.1", "185.220.101.2", "185.220.101.3",
			"199.249.230.1", "199.249.230.2",
			"193.189.100.1", "193.189.100.2",
		}
		for _, ip := range knownTORs {
			r.torList[ip] = true
		}
	}
	r.lastUpdated = time.Now()
}

func (r *IPReputation) loadVPNProxyLists() {
	// Placeholder – would load from free VPN/Proxy lists.
	// For now, use datacenter ranges as a proxy.
}

func (r *IPReputation) CheckIP(ipStr string) *IPInfo {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil
	}

	info := &IPInfo{
		IP:          ipStr,
		LastUpdated: time.Now(),
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	info.IsTOR = r.torList[ipStr]
	info.IsDataCenter = r.isInDatacenterRange(ip)
	// Treat datacenter IPs as potential VPN/Proxy
	info.IsVPN = info.IsDataCenter
	info.IsProxy = info.IsDataCenter

	info.RiskScore = r.calculateRiskScore(info)
	return info
}

func (r *IPReputation) isInDatacenterRange(ip net.IP) bool {
	for _, ipnet := range r.datacenterRanges {
		if ipnet.Contains(ip) {
			return true
		}
	}
	return false
}

func (r *IPReputation) calculateRiskScore(info *IPInfo) int {
	score := 0
	if info.IsTOR {
		score += 40
	}
	if info.IsVPN {
		score += 30
	}
	if info.IsProxy {
		score += 25
	}
	if info.IsDataCenter {
		score += 20
	}
	return score
}

func (r *IPReputation) IsTOR(ip string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.torList[ip]
}

func (r *IPReputation) IsVPN(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	return r.isInDatacenterRange(ip)
}

func (r *IPReputation) IsProxy(ipStr string) bool {
	return r.IsVPN(ipStr)
}

func (r *IPReputation) IsDataCenterIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	return r.isInDatacenterRange(ip)
}

func (r *IPReputation) QuickCheck(ipStr string) (bool, int) {
	info := r.CheckIP(ipStr)
	if info == nil {
		return false, 0
	}
	isRisky := info.RiskScore >= 30
	return isRisky, info.RiskScore
}
