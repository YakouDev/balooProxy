package firewall

import (
	"fmt"
	"goProxy/core/domains"
	"net/http"
	"sync"
	"time"
)

var (
	MetricsEnabled = false
	MetricsPort    = 9090
	
	// Metrics data
	MetricsData = &Metrics{
		PerIPMetrics:      make(map[string]*IPMetrics),
		DomainMetrics:     make(map[string]*DomainMetrics),
		GlobalMetrics:    &GlobalMetrics{},
		mutex:            &sync.RWMutex{},
	}
)

type Metrics struct {
	PerIPMetrics   map[string]*IPMetrics
	DomainMetrics  map[string]*DomainMetrics
	GlobalMetrics  *GlobalMetrics
	mutex          *sync.RWMutex
}

type IPMetrics struct {
	IP                    string
	TotalRequests         int64
	BypassedRequests      int64
	BlockedRequests       int64
	ChallengeFailures     int64
	RateLimitHits         int64
	ReputationScore       int
	LastSeen              time.Time
	RequestsPerSecond     float64
	AverageResponseTime   float64
}

type DomainMetrics struct {
	DomainName            string
	TotalRequests         int64
	BypassedRequests      int64
	BlockedRequests       int64
	RequestsPerSecond     float64
	BypassedPerSecond     float64
	CurrentStage          int
	IsUnderAttack         bool
	AttackStartTime       *time.Time
	TopAttackingIPs        []string
	TopCountries          []string
	TopASNs               []int
}

type GlobalMetrics struct {
	TotalConnections      int64
	ActiveConnections     int64
	TotalRequests         int64
	RequestsPerSecond     float64
	CPUUsage              float64
	MemoryUsage           float64
	ActiveGoroutines      int
	Uptime                time.Duration
	StartTime             time.Time
}

// RecordIPRequest records a request for an IP
func RecordIPRequest(ip string, bypassed bool, blocked bool) {
	if !MetricsEnabled {
		return
	}
	
	MetricsData.mutex.Lock()
	defer MetricsData.mutex.Unlock()
	
	metrics, exists := MetricsData.PerIPMetrics[ip]
	if !exists {
		metrics = &IPMetrics{
			IP:            ip,
			LastSeen:      time.Now(),
		}
		MetricsData.PerIPMetrics[ip] = metrics
	}
	
	metrics.TotalRequests++
	if bypassed {
		metrics.BypassedRequests++
	}
	if blocked {
		metrics.BlockedRequests++
	}
	metrics.LastSeen = time.Now()
}

// RecordIPChallengeFailure records a challenge failure for an IP
func RecordIPChallengeFailure(ip string) {
	if !MetricsEnabled {
		return
	}
	
	MetricsData.mutex.Lock()
	defer MetricsData.mutex.Unlock()
	
	metrics, exists := MetricsData.PerIPMetrics[ip]
	if !exists {
		metrics = &IPMetrics{
			IP:            ip,
			LastSeen:      time.Now(),
		}
		MetricsData.PerIPMetrics[ip] = metrics
	}
	
	metrics.ChallengeFailures++
}

// RecordIPRateLimitHit records a rate limit hit for an IP
func RecordIPRateLimitHit(ip string) {
	if !MetricsEnabled {
		return
	}
	
	MetricsData.mutex.Lock()
	defer MetricsData.mutex.Unlock()
	
	metrics, exists := MetricsData.PerIPMetrics[ip]
	if !exists {
		metrics = &IPMetrics{
			IP:            ip,
			LastSeen:      time.Now(),
		}
		MetricsData.PerIPMetrics[ip] = metrics
	}
	
	metrics.RateLimitHits++
}

// UpdateIPReputationScore updates reputation score in metrics
func UpdateIPReputationScore(ip string, score int) {
	if !MetricsEnabled {
		return
	}
	
	MetricsData.mutex.Lock()
	defer MetricsData.mutex.Unlock()
	
	metrics, exists := MetricsData.PerIPMetrics[ip]
	if !exists {
		metrics = &IPMetrics{
			IP:            ip,
			LastSeen:      time.Now(),
		}
		MetricsData.PerIPMetrics[ip] = metrics
	}
	
	metrics.ReputationScore = score
}

// UpdateDomainMetrics updates domain-level metrics
func UpdateDomainMetrics(domainName string) {
	if !MetricsEnabled {
		return
	}
	
	Mutex.RLock()
	domainData, exists := domains.DomainsData[domainName]
	Mutex.RUnlock()
	
	if !exists {
		return
	}
	
	MetricsData.mutex.Lock()
	defer MetricsData.mutex.Unlock()
	
	metrics, exists := MetricsData.DomainMetrics[domainName]
	if !exists {
		metrics = &DomainMetrics{
			DomainName: domainName,
		}
		MetricsData.DomainMetrics[domainName] = metrics
	}
	
	metrics.TotalRequests = int64(domainData.TotalRequests)
	metrics.BypassedRequests = int64(domainData.BypassedRequests)
	metrics.RequestsPerSecond = float64(domainData.RequestsPerSecond)
	metrics.BypassedPerSecond = float64(domainData.RequestsBypassedPerSecond)
	metrics.CurrentStage = domainData.Stage
	metrics.IsUnderAttack = domainData.RawAttack || domainData.BypassAttack
	
	if metrics.IsUnderAttack && metrics.AttackStartTime == nil {
		now := time.Now()
		metrics.AttackStartTime = &now
	} else if !metrics.IsUnderAttack {
		metrics.AttackStartTime = nil
	}
}

// UpdateGlobalMetrics updates global metrics
func UpdateGlobalMetrics() {
	if !MetricsEnabled {
		return
	}
	
	MetricsData.mutex.Lock()
	defer MetricsData.mutex.Unlock()
	
	// Update connection counts
	MetricsData.GlobalMetrics.ActiveConnections = int64(len(ConnectionTracker.ActiveConnections))
	
	// Update from domains
	totalRPS := 0.0
	totalRequests := int64(0)
	
	Mutex.RLock()
	for _, domainData := range domains.DomainsData {
		totalRPS += float64(domainData.RequestsPerSecond)
		totalRequests += int64(domainData.TotalRequests)
	}
	Mutex.RUnlock()
	
	MetricsData.GlobalMetrics.RequestsPerSecond = totalRPS
	MetricsData.GlobalMetrics.TotalRequests = totalRequests
	
	// Update uptime
	if MetricsData.GlobalMetrics.StartTime.IsZero() {
		MetricsData.GlobalMetrics.StartTime = time.Now()
	}
	MetricsData.GlobalMetrics.Uptime = time.Since(MetricsData.GlobalMetrics.StartTime)
}

// GetTopAttackingIPs returns top N attacking IPs
func GetTopAttackingIPs(n int) []string {
	if !MetricsEnabled {
		return []string{}
	}
	
	MetricsData.mutex.RLock()
	defer MetricsData.mutex.RUnlock()
	
	// Simple implementation - return IPs with most blocked requests
	// In production, you might want more sophisticated ranking
	ips := make([]string, 0, len(MetricsData.PerIPMetrics))
	for ip, metrics := range MetricsData.PerIPMetrics {
		if metrics.BlockedRequests > 0 {
			ips = append(ips, ip)
		}
	}
	
	// Sort by blocked requests (simplified)
	if len(ips) > n {
		return ips[:n]
	}
	return ips
}

// CleanupOldIPMetrics removes old IP metrics entries
func CleanupOldIPMetrics() {
	if !MetricsEnabled {
		return
	}
	
	MetricsData.mutex.Lock()
	defer MetricsData.mutex.Unlock()
	
	cutoff := time.Now().Add(-24 * time.Hour)
	for ip, metrics := range MetricsData.PerIPMetrics {
		if metrics.LastSeen.Before(cutoff) {
			delete(MetricsData.PerIPMetrics, ip)
		}
	}
}

// StartMetricsCleanupRoutine starts background cleanup routine
func StartMetricsCleanupRoutine() {
	if !MetricsEnabled {
		return
	}
	
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		
		for range ticker.C {
			CleanupOldIPMetrics()
			UpdateGlobalMetrics()
		}
	}()
}

// StartMetricsUpdateRoutine starts routine to update metrics periodically
func StartMetricsUpdateRoutine() {
	if !MetricsEnabled {
		return
	}
	
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		
		for range ticker.C {
			Mutex.RLock()
			for domainName := range domains.DomainsData {
				UpdateDomainMetrics(domainName)
			}
			Mutex.RUnlock()
			UpdateGlobalMetrics()
		}
	}()
}

// StartPrometheusServer starts HTTP server for Prometheus metrics export
func StartPrometheusServer() {
	if !MetricsEnabled {
		return
	}
	
	http.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		
		MetricsData.mutex.RLock()
		defer MetricsData.mutex.RUnlock()
		
		// Global metrics
		fmt.Fprintf(w, "# HELP balooproxy_total_requests Total number of requests\n")
		fmt.Fprintf(w, "# TYPE balooproxy_total_requests counter\n")
		fmt.Fprintf(w, "balooproxy_total_requests %d\n", MetricsData.GlobalMetrics.TotalRequests)
		
		fmt.Fprintf(w, "# HELP balooproxy_requests_per_second Current requests per second\n")
		fmt.Fprintf(w, "# TYPE balooproxy_requests_per_second gauge\n")
		fmt.Fprintf(w, "balooproxy_requests_per_second %.2f\n", MetricsData.GlobalMetrics.RequestsPerSecond)
		
		fmt.Fprintf(w, "# HELP balooproxy_active_connections Current active connections\n")
		fmt.Fprintf(w, "# TYPE balooproxy_active_connections gauge\n")
		fmt.Fprintf(w, "balooproxy_active_connections %d\n", MetricsData.GlobalMetrics.ActiveConnections)
		
		fmt.Fprintf(w, "# HELP balooproxy_uptime_seconds Uptime in seconds\n")
		fmt.Fprintf(w, "# TYPE balooproxy_uptime_seconds gauge\n")
		fmt.Fprintf(w, "balooproxy_uptime_seconds %.0f\n", MetricsData.GlobalMetrics.Uptime.Seconds())
		
		// Domain metrics
		for domainName, domainMetrics := range MetricsData.DomainMetrics {
			fmt.Fprintf(w, "# HELP balooproxy_domain_requests_total Total requests per domain\n")
			fmt.Fprintf(w, "# TYPE balooproxy_domain_requests_total counter\n")
			fmt.Fprintf(w, "balooproxy_domain_requests_total{domain=\"%s\"} %d\n", domainName, domainMetrics.TotalRequests)
			
			fmt.Fprintf(w, "# HELP balooproxy_domain_bypassed_total Total bypassed requests per domain\n")
			fmt.Fprintf(w, "# TYPE balooproxy_domain_bypassed_total counter\n")
			fmt.Fprintf(w, "balooproxy_domain_bypassed_total{domain=\"%s\"} %d\n", domainName, domainMetrics.BypassedRequests)
			
			fmt.Fprintf(w, "# HELP balooproxy_domain_stage Current stage per domain\n")
			fmt.Fprintf(w, "# TYPE balooproxy_domain_stage gauge\n")
			fmt.Fprintf(w, "balooproxy_domain_stage{domain=\"%s\"} %d\n", domainName, domainMetrics.CurrentStage)
			
			fmt.Fprintf(w, "# HELP balooproxy_domain_under_attack Whether domain is under attack\n")
			fmt.Fprintf(w, "# TYPE balooproxy_domain_under_attack gauge\n")
			attackValue := 0
			if domainMetrics.IsUnderAttack {
				attackValue = 1
			}
			fmt.Fprintf(w, "balooproxy_domain_under_attack{domain=\"%s\"} %d\n", domainName, attackValue)
		}
		
		// IP metrics (sample top 100)
		count := 0
		for ip, ipMetrics := range MetricsData.PerIPMetrics {
			if count >= 100 {
				break
			}
			fmt.Fprintf(w, "# HELP balooproxy_ip_total_requests Total requests per IP\n")
			fmt.Fprintf(w, "# TYPE balooproxy_ip_total_requests counter\n")
			fmt.Fprintf(w, "balooproxy_ip_total_requests{ip=\"%s\"} %d\n", ip, ipMetrics.TotalRequests)
			
			fmt.Fprintf(w, "# HELP balooproxy_ip_reputation_score Reputation score per IP\n")
			fmt.Fprintf(w, "# TYPE balooproxy_ip_reputation_score gauge\n")
			fmt.Fprintf(w, "balooproxy_ip_reputation_score{ip=\"%s\"} %d\n", ip, ipMetrics.ReputationScore)
			count++
		}
	})
	
	addr := fmt.Sprintf(":%d", MetricsPort)
	go func() {
		if err := http.ListenAndServe(addr, nil); err != nil {
			// Log error but don't crash
			fmt.Printf("[Metrics] Failed to start Prometheus server: %v\n", err)
		}
	}()
}
