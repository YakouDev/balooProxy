package firewall

import (
	"goProxy/core/domains"
)

var (
	DynamicDifficultyEnabled = true
	MinDifficulty            = 1
	MaxDifficulty            = 10
	BaseDifficulty           = 5
)

// CalculateDynamicDifficulty calculates PoW difficulty based on reputation and attack intensity
func CalculateDynamicDifficulty(ip string, domainName string, baseDifficulty int) int {
	if !DynamicDifficultyEnabled {
		return baseDifficulty
	}
	
	// Get reputation score
	reputationScore := GetReputationScore(ip)
	
	// Get domain attack status
	Mutex.RLock()
	domainData, exists := domains.DomainsData[domainName]
	Mutex.RUnlock()
	
	if !exists {
		return baseDifficulty
	}
	
	// Calculate difficulty adjustment based on reputation
	// Lower reputation = higher difficulty
	reputationAdjustment := 0
	if reputationScore < 30 {
		reputationAdjustment = +3 // Very suspicious, increase difficulty significantly
	} else if reputationScore < 50 {
		reputationAdjustment = +2 // Suspicious, increase difficulty
	} else if reputationScore < 70 {
		reputationAdjustment = +1 // Slightly suspicious
	} else if reputationScore >= 90 {
		reputationAdjustment = -1 // Good reputation, slightly easier
	}
	
	// Calculate difficulty adjustment based on attack intensity
	attackAdjustment := 0
	if domainData.BypassAttack {
		// Bypass attack is serious, increase difficulty
		attackAdjustment = +2
	} else if domainData.RawAttack {
		// Regular attack, moderate increase
		attackAdjustment = +1
	}
	
	// Calculate difficulty adjustment based on stage
	stageAdjustment := 0
	if domainData.Stage == 3 {
		stageAdjustment = +1 // Stage 3 is most restrictive
	} else if domainData.Stage == 2 {
		stageAdjustment = 0 // Stage 2 is moderate
	} else {
		stageAdjustment = -1 // Stage 1 is least restrictive
	}
	
	// Calculate final difficulty
	finalDifficulty := baseDifficulty + reputationAdjustment + attackAdjustment + stageAdjustment
	
	// Clamp to min/max range
	if finalDifficulty < MinDifficulty {
		finalDifficulty = MinDifficulty
	}
	if finalDifficulty > MaxDifficulty {
		finalDifficulty = MaxDifficulty
	}
	
	return finalDifficulty
}

// GetEffectiveDifficulty returns the effective difficulty for a request
func GetEffectiveDifficulty(ip string, domainName string) int {
	Mutex.RLock()
	domainData, exists := domains.DomainsData[domainName]
	Mutex.RUnlock()
	
	if !exists {
		return BaseDifficulty
	}
	
	baseDiff := domainData.Stage2Difficulty
	if baseDiff == 0 {
		baseDiff = BaseDifficulty
	}
	
	return CalculateDynamicDifficulty(ip, domainName, baseDiff)
}
