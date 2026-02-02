package firewall

import (
	"encoding/binary"
	"encoding/json"
	"sync"
	"time"

	"github.com/boltdb/bolt"
)

var (
	ReputationDB     *bolt.DB
	ReputationScores = make(map[string]*ReputationData)
	ReputationMutex  = &sync.RWMutex{}
	
	// Default reputation settings
	ReputationEnabled     = true
	ReputationMinScore    = 20
	ReputationPersistToDB = true
	ReputationDecayInterval = 3600 // seconds (1 hour)
	ReputationDBPath      = "reputation.db"
	
	// Score adjustments
	ScoreChallengeFailure = -5
	ScoreRateLimitHit    = -3
	ScoreFingerprintMismatch = -10
	ScoreSuccessfulAccess = +1
	ScoreClean24hPeriod   = +10
	
	DefaultReputationScore = 50
	MaxReputationScore     = 100
	MinReputationScore     = 0
)

type ReputationData struct {
	IP            string    `json:"ip"`
	Score         int       `json:"score"`
	LastUpdated   time.Time `json:"last_updated"`
	LastDecay     time.Time `json:"last_decay"`
	TotalRequests int       `json:"total_requests"`
	FailedChallenges int    `json:"failed_challenges"`
	RateLimitHits int       `json:"rate_limit_hits"`
}

// InitReputationDB initializes the BoltDB database for reputation storage
func InitReputationDB() error {
	if !ReputationPersistToDB {
		return nil
	}
	
	var err error
	ReputationDB, err = bolt.Open(ReputationDBPath, 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return err
	}
	
	// Create bucket if it doesn't exist
	err = ReputationDB.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte("reputation"))
		return err
	})
	
	if err != nil {
		return err
	}
	
	// Load existing reputation data from DB
	LoadReputationFromDB()
	
	// Start decay routine
	go ReputationDecayRoutine()
	
	return nil
}

// LoadReputationFromDB loads reputation scores from BoltDB
func LoadReputationFromDB() {
	if !ReputationPersistToDB || ReputationDB == nil {
		return
	}
	
	ReputationMutex.Lock()
	defer ReputationMutex.Unlock()
	
	ReputationDB.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("reputation"))
		if bucket == nil {
			return nil
		}
		
		bucket.ForEach(func(k, v []byte) error {
			var data ReputationData
			if err := json.Unmarshal(v, &data); err == nil {
				ReputationScores[string(k)] = &data
			}
			return nil
		})
		return nil
	})
}

// SaveReputationToDB saves reputation score to BoltDB
func SaveReputationToDB(ip string, data *ReputationData) {
	if !ReputationPersistToDB || ReputationDB == nil {
		return
	}
	
	ReputationDB.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("reputation"))
		if bucket == nil {
			return nil
		}
		
		jsonData, err := json.Marshal(data)
		if err != nil {
			return err
		}
		
		return bucket.Put([]byte(ip), jsonData)
	})
}

// GetReputation gets or creates reputation data for an IP
func GetReputation(ip string) *ReputationData {
	ReputationMutex.RLock()
	data, exists := ReputationScores[ip]
	ReputationMutex.RUnlock()
	
	if !exists {
		// Create new reputation entry
		ReputationMutex.Lock()
		// Double-check after acquiring write lock
		data, exists = ReputationScores[ip]
		if !exists {
			data = &ReputationData{
				IP:          ip,
				Score:       DefaultReputationScore,
				LastUpdated: time.Now(),
				LastDecay:   time.Now(),
			}
			ReputationScores[ip] = data
		}
		ReputationMutex.Unlock()
		
		if !exists && ReputationPersistToDB {
			SaveReputationToDB(ip, data)
		}
	}
	
	return data
}

// UpdateReputation updates reputation score for an IP
func UpdateReputation(ip string, scoreChange int, reason string) {
	if !ReputationEnabled {
		return
	}
	
	ReputationMutex.Lock()
	defer ReputationMutex.Unlock()
	
	data := GetReputation(ip)
	
	// Update score
	oldScore := data.Score
	data.Score += scoreChange
	
	// Clamp score between min and max
	if data.Score > MaxReputationScore {
		data.Score = MaxReputationScore
	}
	if data.Score < MinReputationScore {
		data.Score = MinReputationScore
	}
	
	data.LastUpdated = time.Now()
	data.TotalRequests++
	
	// Track specific events
	switch reason {
	case "challenge_failure":
		data.FailedChallenges++
	case "rate_limit_hit":
		data.RateLimitHits++
	case "successful_access":
		// Positive event, no specific tracking needed
	}
	
	ReputationScores[ip] = data
	
	// Save to DB if enabled
	if ReputationPersistToDB {
		SaveReputationToDB(ip, data)
	}
	
	// Log significant changes (can be extended with logging later)
	if oldScore >= ReputationMinScore && data.Score < ReputationMinScore {
		// IP just dropped below threshold - will be blocked on next request
		// Could add logging here if needed
	}
}

// GetReputationScore returns the current reputation score for an IP
func GetReputationScore(ip string) int {
	if !ReputationEnabled {
		return DefaultReputationScore
	}
	
	ReputationMutex.RLock()
	defer ReputationMutex.RUnlock()
	
	data, exists := ReputationScores[ip]
	if !exists {
		return DefaultReputationScore
	}
	
	return data.Score
}

// IsIPBlocked checks if an IP should be blocked based on reputation
func IsIPBlocked(ip string) bool {
	if !ReputationEnabled {
		return false
	}
	
	score := GetReputationScore(ip)
	return score < ReputationMinScore
}

// ReputationDecayRoutine periodically decays reputation scores to allow recovery
func ReputationDecayRoutine() {
	ticker := time.NewTicker(time.Duration(ReputationDecayInterval) * time.Second)
	defer ticker.Stop()
	
	for range ticker.C {
		ReputationMutex.Lock()
		
		now := time.Now()
		for ip, data := range ReputationScores {
			// Only decay if last decay was more than interval ago
			if now.Sub(data.LastDecay) >= time.Duration(ReputationDecayInterval)*time.Second {
				// Decay: move score towards default (50)
				if data.Score < DefaultReputationScore {
					// Increase score slightly (recovery)
					data.Score += 1
					if data.Score > DefaultReputationScore {
						data.Score = DefaultReputationScore
					}
				} else if data.Score > DefaultReputationScore {
					// Decrease score slightly (decay from high score)
					data.Score -= 1
					if data.Score < DefaultReputationScore {
						data.Score = DefaultReputationScore
					}
				}
				
				data.LastDecay = now
				ReputationScores[ip] = data
				
				// Save to DB
				if ReputationPersistToDB {
					SaveReputationToDB(ip, data)
				}
			}
		}
		
		ReputationMutex.Unlock()
	}
}

// CleanupOldReputation removes reputation entries older than specified days
func CleanupOldReputation(daysOld int) {
	if !ReputationPersistToDB || ReputationDB == nil {
		return
	}
	
	ReputationMutex.Lock()
	defer ReputationMutex.Unlock()
	
	cutoff := time.Now().AddDate(0, 0, -daysOld)
	
	for ip, data := range ReputationScores {
		if data.LastUpdated.Before(cutoff) && data.Score == DefaultReputationScore {
			// Remove entries that are old and at default score
			delete(ReputationScores, ip)
			
			ReputationDB.Update(func(tx *bolt.Tx) error {
				bucket := tx.Bucket([]byte("reputation"))
				if bucket != nil {
					return bucket.Delete([]byte(ip))
				}
				return nil
			})
		}
	}
}

// CloseReputationDB closes the BoltDB connection
func CloseReputationDB() error {
	if ReputationDB != nil {
		return ReputationDB.Close()
	}
	return nil
}

// Helper function to convert int to byte slice for BoltDB
func itob(v int) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(v))
	return b
}

// Helper function to convert byte slice to int from BoltDB
func btoi(b []byte) int {
	return int(binary.BigEndian.Uint64(b))
}
