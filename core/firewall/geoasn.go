package firewall

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

var (
	GeoFilteringEnabled = false
	GeoFilterMode       = "blacklist" // "whitelist" or "blacklist"
	AllowedCountries   = []string{}
	BlockedCountries   = []string{}
	BlockedASN         = []int{}
	ChallengeUnknown   = false
	
	// Cache for geo data
	GeoCache      = make(map[string]*GeoData)
	GeoCacheMutex = &sync.RWMutex{}
	GeoCacheTTL   = 24 * time.Hour // Cache for 24 hours
	
	// API endpoint
	GeoAPIEndpoint = "https://api.ipiz.net"
)

type GeoData struct {
	ASN            int     `json:"asn"`
	City           string  `json:"city"`
	Continent      string  `json:"continent"`
	ContinentCode  string  `json:"continent_code"`
	Country        string  `json:"country"`
	CountryCode    string  `json:"country_code"`
	IP             string  `json:"ip"`
	Latitude       float64 `json:"latitude"`
	Longitude      float64 `json:"longitude"`
	OrgCountry     string  `json:"org_country"`
	OrgCountryCode string  `json:"org_country_code"`
	OrgName        string  `json:"org_name"`
	Postal         string  `json:"postal"`
	Region         string  `json:"region"`
	Status         string  `json:"status"`
	Timezone       string  `json:"timezone"`
	CachedAt       time.Time
}

// GetGeoData fetches geo data for an IP (with caching)
func GetGeoData(ip string) (*GeoData, error) {
	if !GeoFilteringEnabled {
		return nil, nil
	}
	
	// Check cache first
	GeoCacheMutex.RLock()
	cached, exists := GeoCache[ip]
	GeoCacheMutex.RUnlock()
	
	if exists && time.Since(cached.CachedAt) < GeoCacheTTL {
		return cached, nil
	}
	
	// Fetch from API
	url := fmt.Sprintf("%s/%s", GeoAPIEndpoint, ip)
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch geo data: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("geo API returned status %d", resp.StatusCode)
	}
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}
	
	var geoData GeoData
	if err := json.Unmarshal(body, &geoData); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	
	if geoData.Status != "ok" {
		return nil, fmt.Errorf("geo API returned error status")
	}
	
	// Cache the result
	geoData.CachedAt = time.Now()
	GeoCacheMutex.Lock()
	GeoCache[ip] = &geoData
	GeoCacheMutex.Unlock()
	
	return &geoData, nil
}

// CheckGeoFilter checks if IP should be blocked based on geo/ASN filtering
func CheckGeoFilter(ip string) (bool, string) {
	if !GeoFilteringEnabled {
		return false, ""
	}
	
	geoData, err := GetGeoData(ip)
	if err != nil {
		// If API fails and ChallengeUnknown is enabled, challenge instead of blocking
		if ChallengeUnknown {
			return true, "challenge" // Challenge unknown IPs
		}
		// If API fails and ChallengeUnknown is false, allow (fail open)
		return false, ""
	}
	
	// Check ASN blocking
	for _, blockedASN := range BlockedASN {
		if geoData.ASN == blockedASN {
			return true, fmt.Sprintf("ASN %d is blocked", blockedASN)
		}
	}
	
	// Check country filtering
	if GeoFilterMode == "whitelist" {
		// Whitelist mode: only allow specified countries
		allowed := false
		for _, allowedCountry := range AllowedCountries {
			if strings.EqualFold(geoData.CountryCode, allowedCountry) {
				allowed = true
				break
			}
		}
		if !allowed {
			return true, fmt.Sprintf("Country %s (%s) is not whitelisted", geoData.Country, geoData.CountryCode)
		}
	} else {
		// Blacklist mode: block specified countries
		for _, blockedCountry := range BlockedCountries {
			if strings.EqualFold(geoData.CountryCode, blockedCountry) {
				return true, fmt.Sprintf("Country %s (%s) is blocked", geoData.Country, geoData.CountryCode)
			}
		}
	}
	
	return false, ""
}

// GetIPCountry returns country code for an IP (cached)
func GetIPCountry(ip string) string {
	if !GeoFilteringEnabled {
		return ""
	}
	
	geoData, err := GetGeoData(ip)
	if err != nil {
		return ""
	}
	
	return geoData.CountryCode
}

// GetIPASN returns ASN for an IP (cached)
func GetIPASN(ip string) int {
	if !GeoFilteringEnabled {
		return 0
	}
	
	geoData, err := GetGeoData(ip)
	if err != nil {
		return 0
	}
	
	return geoData.ASN
}

// CleanupGeoCache removes old cache entries
func CleanupGeoCache() {
	GeoCacheMutex.Lock()
	defer GeoCacheMutex.Unlock()
	
	now := time.Now()
	for ip, data := range GeoCache {
		if now.Sub(data.CachedAt) > GeoCacheTTL*2 {
			delete(GeoCache, ip)
		}
	}
}

// StartGeoCacheCleanupRoutine starts background cleanup routine
func StartGeoCacheCleanupRoutine() {
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		
		for range ticker.C {
			CleanupGeoCache()
		}
	}()
}
