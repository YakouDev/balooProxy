package firewall

import (
	"goProxy/core/proxy"
	"sync"
	"time"
)

var (
	MultiWindowEnabled = true
	
	// Window durations in seconds
	BurstWindow  = 10  // 10 seconds
	ShortWindow  = 60  // 1 minute
	MediumWindow = 300 // 5 minutes
	LongWindow   = 3600 // 1 hour
	
	// Multi-window tracking maps
	BurstWindowIps  = make(map[int]map[string]int)  // timestamp -> IP -> count
	ShortWindowIps  = make(map[int]map[string]int)
	MediumWindowIps = make(map[int]map[string]int)
	LongWindowIps   = make(map[int]map[string]int)
	
	MultiWindowMutex = &sync.RWMutex{}
)

// RecordRequest records a request in all active windows
func RecordRequest(ip string) {
	if !MultiWindowEnabled {
		return
	}
	
	now := time.Now()
	burstTs := int(now.Unix()) / BurstWindow * BurstWindow
	shortTs := int(now.Unix()) / ShortWindow * ShortWindow
	mediumTs := int(now.Unix()) / MediumWindow * MediumWindow
	longTs := int(now.Unix()) / LongWindow * LongWindow
	
	MultiWindowMutex.Lock()
	defer MultiWindowMutex.Unlock()
	
	// Burst window
	if BurstWindowIps[burstTs] == nil {
		BurstWindowIps[burstTs] = make(map[string]int)
	}
	BurstWindowIps[burstTs][ip]++
	
	// Short window
	if ShortWindowIps[shortTs] == nil {
		ShortWindowIps[shortTs] = make(map[string]int)
	}
	ShortWindowIps[shortTs][ip]++
	
	// Medium window
	if MediumWindowIps[mediumTs] == nil {
		MediumWindowIps[mediumTs] = make(map[string]int)
	}
	MediumWindowIps[mediumTs][ip]++
	
	// Long window
	if LongWindowIps[longTs] == nil {
		LongWindowIps[longTs] = make(map[string]int)
	}
	LongWindowIps[longTs][ip]++
}

// GetRequestCount returns request count for IP in specified window
func GetRequestCount(ip string, window string) int {
	if !MultiWindowEnabled {
		return 0
	}
	
	now := time.Now()
	var ts int
	var windowMap map[int]map[string]int
	
	switch window {
	case "burst":
		ts = int(now.Unix()) / BurstWindow * BurstWindow
		windowMap = BurstWindowIps
	case "short":
		ts = int(now.Unix()) / ShortWindow * ShortWindow
		windowMap = ShortWindowIps
	case "medium":
		ts = int(now.Unix()) / MediumWindow * MediumWindow
		windowMap = MediumWindowIps
	case "long":
		ts = int(now.Unix()) / LongWindow * LongWindow
		windowMap = LongWindowIps
	default:
		return 0
	}
	
	MultiWindowMutex.RLock()
	defer MultiWindowMutex.RUnlock()
	
	if windowMap[ts] == nil {
		return 0
	}
	
	return windowMap[ts][ip]
}

// CheckBurstLimit checks if IP exceeds burst limit
func CheckBurstLimit(ip string, limit int) bool {
	if !MultiWindowEnabled {
		return false
	}
	
	count := GetRequestCount(ip, "burst")
	return count >= limit
}

// CheckShortTermLimit checks if IP exceeds short-term limit
func CheckShortTermLimit(ip string, limit int) bool {
	if !MultiWindowEnabled {
		return false
	}
	
	count := GetRequestCount(ip, "short")
	return count >= limit
}

// CheckMediumTermLimit checks if IP exceeds medium-term limit
func CheckMediumTermLimit(ip string, limit int) bool {
	if !MultiWindowEnabled {
		return false
	}
	
	count := GetRequestCount(ip, "medium")
	return count >= limit
}

// CheckLongTermLimit checks if IP exceeds long-term limit
func CheckLongTermLimit(ip string, limit int) bool {
	if !MultiWindowEnabled {
		return false
	}
	
	count := GetRequestCount(ip, "long")
	return count >= limit
}

// CleanupOldWindows removes old window entries
func CleanupOldWindows() {
	MultiWindowMutex.Lock()
	defer MultiWindowMutex.Unlock()
	
	now := int(time.Now().Unix())
	
	// Cleanup burst windows (keep last 2 windows)
	burstCutoff := (now / BurstWindow * BurstWindow) - BurstWindow*2
	for ts := range BurstWindowIps {
		if ts < burstCutoff {
			delete(BurstWindowIps, ts)
		}
	}
	
	// Cleanup short windows (keep last 2 windows)
	shortCutoff := (now / ShortWindow * ShortWindow) - ShortWindow*2
	for ts := range ShortWindowIps {
		if ts < shortCutoff {
			delete(ShortWindowIps, ts)
		}
	}
	
	// Cleanup medium windows (keep last 2 windows)
	mediumCutoff := (now / MediumWindow * MediumWindow) - MediumWindow*2
	for ts := range MediumWindowIps {
		if ts < mediumCutoff {
			delete(MediumWindowIps, ts)
		}
	}
	
	// Cleanup long windows (keep last 2 windows)
	longCutoff := (now / LongWindow * LongWindow) - LongWindow*2
	for ts := range LongWindowIps {
		if ts < longCutoff {
			delete(LongWindowIps, ts)
		}
	}
}

// StartMultiWindowCleanupRoutine starts background cleanup routine
func StartMultiWindowCleanupRoutine() {
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		
		for range ticker.C {
			CleanupOldWindows()
		}
	}()
}
