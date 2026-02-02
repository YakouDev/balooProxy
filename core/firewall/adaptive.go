package firewall

import (
	"goProxy/core/domains"
	"goProxy/core/proxy"
	"sync"
	"time"
)

var (
	AdaptiveRateLimitEnabled = true
	AdaptiveBaseMultiplier    = 1.0
	AdaptiveAttackMultiplier  = 0.3
	AdaptiveDecayRate         = 0.1
	AdaptiveLearningEnabled   = true
	
	// Current adaptive multipliers per domain
	AdaptiveMultipliers = make(map[string]float64)
	AdaptiveMutex       = &sync.RWMutex{}
	
	// Whitelist learning
	IPWhitelist = make(map[string]*WhitelistEntry)
	WhitelistMutex = &sync.RWMutex{}
)

type WhitelistEntry struct {
	IP            string
	AddedAt       time.Time
	RequestCount  int
	SuccessRate   float64
	LastSeen      time.Time
}

// GetAdaptiveMultiplier returns the current adaptive multiplier for a domain
func GetAdaptiveMultiplier(domainName string) float64 {
	if !AdaptiveRateLimitEnabled {
		return AdaptiveBaseMultiplier
	}
	
	AdaptiveMutex.RLock()
	defer AdaptiveMutex.RUnlock()
	
	multiplier, exists := AdaptiveMultipliers[domainName]
	if !exists {
		return AdaptiveBaseMultiplier
	}
	
	return multiplier
}

// UpdateAdaptiveMultiplier updates the adaptive multiplier based on attack status
func UpdateAdaptiveMultiplier(domainName string, isUnderAttack bool, bypassAttack bool) {
	if !AdaptiveRateLimitEnabled {
		return
	}
	
	AdaptiveMutex.Lock()
	defer AdaptiveMutex.Unlock()
	
	currentMultiplier, exists := AdaptiveMultipliers[domainName]
	if !exists {
		currentMultiplier = AdaptiveBaseMultiplier
	}
	
	if isUnderAttack {
		// Reduce multiplier when under attack (more restrictive)
		if bypassAttack {
			// Bypass attack is more serious, reduce multiplier more aggressively
			newMultiplier := currentMultiplier * AdaptiveAttackMultiplier
			if newMultiplier < AdaptiveAttackMultiplier {
				newMultiplier = AdaptiveAttackMultiplier
			}
			AdaptiveMultipliers[domainName] = newMultiplier
		} else {
			// Regular attack, moderate reduction
			newMultiplier := currentMultiplier * 0.7
			if newMultiplier < AdaptiveAttackMultiplier*1.5 {
				newMultiplier = AdaptiveAttackMultiplier * 1.5
			}
			AdaptiveMultipliers[domainName] = newMultiplier
		}
	} else {
		// Gradually recover multiplier when not under attack
		if currentMultiplier < AdaptiveBaseMultiplier {
			// Decay towards base multiplier
			decayAmount := (AdaptiveBaseMultiplier - currentMultiplier) * AdaptiveDecayRate
			newMultiplier := currentMultiplier + decayAmount
			if newMultiplier > AdaptiveBaseMultiplier {
				newMultiplier = AdaptiveBaseMultiplier
			}
			AdaptiveMultipliers[domainName] = newMultiplier
		}
	}
}

// GetAdaptiveRateLimit calculates the effective rate limit using adaptive multiplier
func GetAdaptiveRateLimit(baseLimit int, domainName string) int {
	if !AdaptiveRateLimitEnabled {
		return baseLimit
	}
	
	multiplier := GetAdaptiveMultiplier(domainName)
	adaptiveLimit := float64(baseLimit) * multiplier
	
	// Ensure minimum limit
	if adaptiveLimit < float64(baseLimit)*AdaptiveAttackMultiplier {
		adaptiveLimit = float64(baseLimit) * AdaptiveAttackMultiplier
	}
	
	return int(adaptiveLimit)
}

// CheckWhitelist checks if an IP is whitelisted
func CheckWhitelist(ip string) bool {
	if !AdaptiveLearningEnabled {
		return false
	}
	
	WhitelistMutex.RLock()
	defer WhitelistMutex.RUnlock()
	
	entry, exists := IPWhitelist[ip]
	if !exists {
		return false
	}
	
	// Check if whitelist entry is still valid (not expired)
	if time.Since(entry.LastSeen) > 24*time.Hour {
		return false
	}
	
	return true
}

// UpdateWhitelistLearning updates whitelist based on IP behavior
func UpdateWhitelistLearning(ip string, success bool) {
	if !AdaptiveLearningEnabled {
		return
	}
	
	WhitelistMutex.Lock()
	defer WhitelistMutex.Unlock()
	
	entry, exists := IPWhitelist[ip]
	if !exists {
		entry = &WhitelistEntry{
			IP:           ip,
			AddedAt:      time.Now(),
			RequestCount: 0,
			SuccessRate:  0.0,
			LastSeen:     time.Now(),
		}
		IPWhitelist[ip] = entry
	}
	
	entry.RequestCount++
	entry.LastSeen = time.Now()
	
	// Calculate success rate
	if success {
		entry.SuccessRate = float64(entry.RequestCount-1)/float64(entry.RequestCount)*entry.SuccessRate + 1.0/float64(entry.RequestCount)
	} else {
		entry.SuccessRate = float64(entry.RequestCount-1)/float64(entry.RequestCount)*entry.SuccessRate
	}
	
	// Auto-whitelist if IP has high success rate and many requests
	if entry.RequestCount >= 100 && entry.SuccessRate >= 0.95 {
		// IP is consistently good, keep in whitelist
		IPWhitelist[ip] = entry
	} else if entry.RequestCount < 10 {
		// Not enough data, keep tracking
		IPWhitelist[ip] = entry
	} else if entry.SuccessRate < 0.5 {
		// IP has low success rate, remove from whitelist
		delete(IPWhitelist, ip)
	}
}

// CleanupWhitelist removes expired whitelist entries
func CleanupWhitelist() {
	WhitelistMutex.Lock()
	defer WhitelistMutex.Unlock()
	
	now := time.Now()
	for ip, entry := range IPWhitelist {
		if now.Sub(entry.LastSeen) > 7*24*time.Hour {
			// Remove entries not seen for 7 days
			delete(IPWhitelist, ip)
		}
	}
}

// StartAdaptiveRateLimitRoutine starts background routine to update adaptive multipliers
func StartAdaptiveRateLimitRoutine() {
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		
		for range ticker.C {
			Mutex.RLock()
			for domainName, domainData := range domains.DomainsData {
				isUnderAttack := domainData.RawAttack || domainData.BypassAttack
				UpdateAdaptiveMultiplier(domainName, isUnderAttack, domainData.BypassAttack)
			}
			Mutex.RUnlock()
			
			// Cleanup whitelist periodically
			CleanupWhitelist()
		}
	}()
}
