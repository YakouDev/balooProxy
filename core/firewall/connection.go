package firewall

import (
	"sync"
	"time"
)

var (
	// Connection tracking per IP
	ConnectionTracker = &ConnectionLimiter{
		ActiveConnections:   make(map[string]int),
		ConnectionRate:      make(map[string][]time.Time),
		HalfOpenConnections: make(map[string]int),
		LastCleanup:        time.Now(),
		mutex:              &sync.RWMutex{},
	}

	// Default limits (will be overridden by config)
	MaxConcurrentConnPerIP     = 100
	MaxConnRatePerIP           = 10 // per second
	MaxHalfOpenPerIP           = 20
	EnableSynFloodProtection   = true
	ConnectionRateWindow       = 1 * time.Second
	ConnectionCleanupInterval  = 30 * time.Second
)

type ConnectionLimiter struct {
	ActiveConnections   map[string]int       // IP -> count
	ConnectionRate      map[string][]time.Time // IP -> timestamps (sliding window)
	HalfOpenConnections map[string]int       // IP -> count
	LastCleanup         time.Time
	mutex               *sync.RWMutex
}

// CheckConnectionLimit checks if IP can establish new connection
// Returns true if allowed, false if blocked
func (cl *ConnectionLimiter) CheckConnectionLimit(ip string) bool {
	cl.mutex.Lock()
	defer cl.mutex.Unlock()

	// Check concurrent connections limit
	if cl.ActiveConnections[ip] >= MaxConcurrentConnPerIP {
		return false
	}

	// Check connection rate limit
	now := time.Now()
	rateTimestamps := cl.ConnectionRate[ip]
	
	// Remove timestamps outside the window
	validTimestamps := []time.Time{}
	for _, ts := range rateTimestamps {
		if now.Sub(ts) < ConnectionRateWindow {
			validTimestamps = append(validTimestamps, ts)
		}
	}
	cl.ConnectionRate[ip] = validTimestamps

	// Check if rate limit exceeded
	if len(validTimestamps) >= MaxConnRatePerIP {
		return false
	}

	// Check half-open connections (SYN flood protection)
	if EnableSynFloodProtection {
		if cl.HalfOpenConnections[ip] >= MaxHalfOpenPerIP {
			return false
		}
	}

	return true
}

// IncrementConnection increments active connection count for IP
func (cl *ConnectionLimiter) IncrementConnection(ip string) {
	cl.mutex.Lock()
	defer cl.mutex.Unlock()
	cl.ActiveConnections[ip]++
	cl.ConnectionRate[ip] = append(cl.ConnectionRate[ip], time.Now())
}

// DecrementConnection decrements active connection count for IP
func (cl *ConnectionLimiter) DecrementConnection(ip string) {
	cl.mutex.Lock()
	defer cl.mutex.Unlock()
	if cl.ActiveConnections[ip] > 0 {
		cl.ActiveConnections[ip]--
	}
	if cl.ActiveConnections[ip] == 0 {
		delete(cl.ActiveConnections, ip)
	}
}

// IncrementHalfOpen increments half-open connection count (SYN received)
func (cl *ConnectionLimiter) IncrementHalfOpen(ip string) {
	if !EnableSynFloodProtection {
		return
	}
	cl.mutex.Lock()
	defer cl.mutex.Unlock()
	cl.HalfOpenConnections[ip]++
}

// DecrementHalfOpen decrements half-open connection count (connection established or timeout)
func (cl *ConnectionLimiter) DecrementHalfOpen(ip string) {
	if !EnableSynFloodProtection {
		return
	}
	cl.mutex.Lock()
	defer cl.mutex.Unlock()
	if cl.HalfOpenConnections[ip] > 0 {
		cl.HalfOpenConnections[ip]--
	}
	if cl.HalfOpenConnections[ip] == 0 {
		delete(cl.HalfOpenConnections, ip)
	}
}

// GetConnectionCount returns current active connection count for IP
func (cl *ConnectionLimiter) GetConnectionCount(ip string) int {
	cl.mutex.RLock()
	defer cl.mutex.RUnlock()
	return cl.ActiveConnections[ip]
}

// CleanupOldEntries removes stale entries from tracking maps
func (cl *ConnectionLimiter) CleanupOldEntries() {
	cl.mutex.Lock()
	defer cl.mutex.Unlock()

	now := time.Now()
	
	// Cleanup connection rate timestamps older than window
	for ip, timestamps := range cl.ConnectionRate {
		validTimestamps := []time.Time{}
		for _, ts := range timestamps {
			if now.Sub(ts) < ConnectionRateWindow {
				validTimestamps = append(validTimestamps, ts)
			}
		}
		if len(validTimestamps) == 0 {
			delete(cl.ConnectionRate, ip)
		} else {
			cl.ConnectionRate[ip] = validTimestamps
		}
	}

	// Cleanup half-open connections (they should timeout naturally, but cleanup stale entries)
	// Half-open connections are cleaned up when connection state changes
}

// StartCleanupRoutine starts background routine to cleanup old entries
func (cl *ConnectionLimiter) StartCleanupRoutine() {
	go func() {
		for {
			time.Sleep(ConnectionCleanupInterval)
			cl.CleanupOldEntries()
		}
	}()
}

