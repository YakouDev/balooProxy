package config

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"goProxy/core/domains"
	"goProxy/core/firewall"
	"goProxy/core/proxy"
	"goProxy/core/server"
	"goProxy/core/utils"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/kor44/gofilter"
)

func Load() {

	file, err := os.Open("config.json")
	if err != nil {
		if os.IsNotExist(err) {
			Generate()
		} else {
			panic(err)
		}
	}
	defer file.Close()
	json.NewDecoder(file).Decode(&domains.Config)

	proxy.Cloudflare = domains.Config.Proxy.Cloudflare

	proxy.CookieSecret = domains.Config.Proxy.Secrets["cookie"]
	if strings.Contains(proxy.CookieSecret, "CHANGE_ME") {
		panic("[ " + utils.PrimaryColor("!") + " ] [ Cookie Secret Contains 'CHANGE_ME', Refusing To Load ]")
	}

	proxy.JSSecret = domains.Config.Proxy.Secrets["javascript"]
	if strings.Contains(proxy.JSSecret, "CHANGE_ME") {
		panic("[ " + utils.PrimaryColor("!") + " ] [ JS Secret Contains 'CHANGE_ME', Refusing To Load ]")
	}

	proxy.CaptchaSecret = domains.Config.Proxy.Secrets["captcha"]
	if strings.Contains(proxy.CaptchaSecret, "CHANGE_ME") {
		panic("[ " + utils.PrimaryColor("!") + " ] [ Captcha Secret Contains 'CHANGE_ME', Refusing To Load ]")
	}

	proxy.AdminSecret = domains.Config.Proxy.AdminSecret
	if strings.Contains(proxy.AdminSecret, "CHANGE_ME") {
		panic("[ " + utils.PrimaryColor("!") + " ] [ Admin Secret Contains 'CHANGE_ME', Refusing To Load ]")
	}

	proxy.APISecret = domains.Config.Proxy.APISecret
	if strings.Contains(proxy.APISecret, "CHANGE_ME") {
		panic("[ " + utils.PrimaryColor("!") + " ] [ API Secret Contains 'CHANGE_ME'. Refusing To Load ]")
	}

	// Check if the Proxy Timeout Config has been set otherwise use default values

	if domains.Config.Proxy.Timeout.Idle != 0 {
		proxy.IdleTimeout = domains.Config.Proxy.Timeout.Idle
		proxy.IdleTimeoutDuration = time.Duration(proxy.IdleTimeout).Abs() * time.Second
	}

	if domains.Config.Proxy.Timeout.Read != 0 {
		proxy.ReadTimeout = domains.Config.Proxy.Timeout.Read
		proxy.ReadTimeoutDuration = time.Duration(proxy.ReadTimeout).Abs() * time.Second
	}

	if domains.Config.Proxy.Timeout.ReadHeader != 0 {
		proxy.ReadHeaderTimeout = domains.Config.Proxy.Timeout.ReadHeader
		proxy.ReadHeaderTimeoutDuration = time.Duration(proxy.ReadHeaderTimeout).Abs() * time.Second
	}

	if domains.Config.Proxy.Timeout.Write != 0 {
		proxy.WriteTimeout = domains.Config.Proxy.Timeout.Write
		proxy.WriteTimeoutDuration = time.Duration(proxy.WriteTimeout).Abs() * time.Second
	}

	// Didn't think anyone would actually read through this mess
	if len(domains.Config.Proxy.Colors) != 0 {
		utils.SetColor(domains.Config.Proxy.Colors)
	}

	if domains.Config.Proxy.RatelimitWindow < 10 {
		domains.Config.Proxy.RatelimitWindow = 10
	}
	proxy.RatelimitWindow = domains.Config.Proxy.RatelimitWindow

	proxy.IPRatelimit = domains.Config.Proxy.Ratelimits["requests"]
	proxy.FPRatelimit = domains.Config.Proxy.Ratelimits["unknownFingerprint"]
	proxy.FailChallengeRatelimit = domains.Config.Proxy.Ratelimits["challengeFailures"]
	proxy.FailRequestRatelimit = domains.Config.Proxy.Ratelimits["noRequestsSent"]

	// Load connection limits from config
	if domains.Config.Proxy.ConnectionLimits.MaxConcurrentPerIP > 0 {
		firewall.MaxConcurrentConnPerIP = domains.Config.Proxy.ConnectionLimits.MaxConcurrentPerIP
	}
	if domains.Config.Proxy.ConnectionLimits.MaxConnectionRatePerIP > 0 {
		firewall.MaxConnRatePerIP = domains.Config.Proxy.ConnectionLimits.MaxConnectionRatePerIP
	}
	if domains.Config.Proxy.ConnectionLimits.MaxHalfOpenPerIP > 0 {
		firewall.MaxHalfOpenPerIP = domains.Config.Proxy.ConnectionLimits.MaxHalfOpenPerIP
	}
	firewall.EnableSynFloodProtection = domains.Config.Proxy.ConnectionLimits.EnableSynFloodProtection

	// Start connection tracker cleanup routine
	firewall.ConnectionTracker.StartCleanupRoutine()

	// Initialize reputation system
	if domains.Config.Proxy.Reputation.Enabled {
		firewall.ReputationEnabled = true
		if domains.Config.Proxy.Reputation.MinScore > 0 {
			firewall.ReputationMinScore = domains.Config.Proxy.Reputation.MinScore
		}
		firewall.ReputationPersistToDB = domains.Config.Proxy.Reputation.PersistToDB
		if domains.Config.Proxy.Reputation.DecayInterval > 0 {
			firewall.ReputationDecayInterval = domains.Config.Proxy.Reputation.DecayInterval
		}
		
		if err := firewall.InitReputationDB(); err != nil {
			fmt.Println("[ " + utils.PrimaryColor("!") + " ] [ Failed to initialize reputation DB: " + err.Error() + " ]")
		}
	}

	// Initialize adaptive rate limiting
	if domains.Config.Proxy.AdaptiveRateLimit.Enabled {
		firewall.AdaptiveRateLimitEnabled = true
		if domains.Config.Proxy.AdaptiveRateLimit.BaseMultiplier > 0 {
			firewall.AdaptiveBaseMultiplier = domains.Config.Proxy.AdaptiveRateLimit.BaseMultiplier
		}
		if domains.Config.Proxy.AdaptiveRateLimit.AttackMultiplier > 0 {
			firewall.AdaptiveAttackMultiplier = domains.Config.Proxy.AdaptiveRateLimit.AttackMultiplier
		}
		if domains.Config.Proxy.AdaptiveRateLimit.DecayRate > 0 {
			firewall.AdaptiveDecayRate = domains.Config.Proxy.AdaptiveRateLimit.DecayRate
		}
		firewall.AdaptiveLearningEnabled = domains.Config.Proxy.AdaptiveRateLimit.LearningEnabled
		
		// Start adaptive rate limit routine
		firewall.StartAdaptiveRateLimitRoutine()
	}

	// Initialize challenge settings
	if domains.Config.Proxy.Challenge.DynamicDifficulty {
		firewall.DynamicDifficultyEnabled = true
	}
	if domains.Config.Proxy.Challenge.MinDifficulty > 0 {
		firewall.MinDifficulty = domains.Config.Proxy.Challenge.MinDifficulty
	}
	if domains.Config.Proxy.Challenge.MaxDifficulty > 0 {
		firewall.MaxDifficulty = domains.Config.Proxy.Challenge.MaxDifficulty
	}

	// Initialize multi-window rate limiting
	if domains.Config.Proxy.RatelimitWindows.Burst > 0 {
		firewall.BurstWindow = domains.Config.Proxy.RatelimitWindows.Burst
	}
	if domains.Config.Proxy.RatelimitWindows.Short > 0 {
		firewall.ShortWindow = domains.Config.Proxy.RatelimitWindows.Short
	}
	if domains.Config.Proxy.RatelimitWindows.Medium > 0 {
		firewall.MediumWindow = domains.Config.Proxy.RatelimitWindows.Medium
	}
	if domains.Config.Proxy.RatelimitWindows.Long > 0 {
		firewall.LongWindow = domains.Config.Proxy.RatelimitWindows.Long
	}
	firewall.MultiWindowEnabled = true
	firewall.StartMultiWindowCleanupRoutine()

	fmt.Println("Loading Fingerprints ...")

	GetFingerprints("https://raw.githubusercontent.com/41Baloo/balooProxy/main/global/fingerprints/known_fingerprints.json", &firewall.KnownFingerprints)
	GetFingerprints("https://raw.githubusercontent.com/41Baloo/balooProxy/main/global/fingerprints/bot_fingerprints.json", &firewall.BotFingerprints)
	GetFingerprints("https://raw.githubusercontent.com/41Baloo/balooProxy/main/global/fingerprints/malicious_fingerprints.json", &firewall.ForbiddenFingerprints)

	for i, domain := range domains.Config.Domains {
		domains.Domains = append(domains.Domains, domain.Name)

		firewallRules := []domains.Rule{}
		rawFirewallRules := domains.Config.Domains[i].FirewallRules
		for index, fwRule := range domains.Config.Domains[i].FirewallRules {

			rule, err := gofilter.NewFilter(fwRule.Expression)
			if err != nil {
				panic("[ " + utils.PrimaryColor("!") + " ] [ Error Loading Custom Firewall Rules For " + domain.Name + " ( Rule " + strconv.Itoa(index) + " ) : " + utils.PrimaryColor(err.Error()) + " ]")
			}

			firewallRules = append(firewallRules, domains.Rule{
				Filter: rule,
				Action: fwRule.Action,
			})
		}

		dProxy := httputil.NewSingleHostReverseProxy(&url.URL{
			Scheme: domain.Scheme,
			Host:   domain.Backend,
		})
		dProxy.Transport = &server.RoundTripper{}

		var cert tls.Certificate = tls.Certificate{}
		if !proxy.Cloudflare {
			var certErr error
			cert, certErr = tls.LoadX509KeyPair(domain.Certificate, domain.Key)
			if certErr != nil {
				panic("[ " + utils.PrimaryColor("!") + " ] [ " + utils.PrimaryColor("Error Loading Certificates: "+certErr.Error()) + " ]")
			}
		}

		domains.DomainsMap.Store(domain.Name, domains.DomainSettings{
			Name: domain.Name,

			CustomRules:    firewallRules,
			RawCustomRules: rawFirewallRules,

			DomainProxy:        dProxy,
			DomainCertificates: cert,
			DomainWebhooks: domains.WebhookSettings{
				URL:            domain.Webhook.URL,
				Name:           domain.Webhook.Name,
				Avatar:         domain.Webhook.Avatar,
				AttackStartMsg: domain.Webhook.AttackStartMsg,
				AttackStopMsg:  domain.Webhook.AttackStopMsg,
			},

			BypassStage1:        domain.BypassStage1,
			BypassStage2:        domain.BypassStage2,
			DisableBypassStage3: domain.DisableBypassStage3,
			DisableRawStage3:    domain.DisableRawStage3,
			DisableBypassStage2: domain.DisableBypassStage2,
			DisableRawStage2:    domain.DisableRawStage2,
		})

		firewall.Mutex.Lock()

		if domain.Stage2Difficulty == 0 {
			domain.Stage2Difficulty = 5
		}

		domains.DomainsData[domain.Name] = domains.DomainData{
			Name:             domain.Name,
			Stage:            1,
			StageManuallySet: false,
			Stage2Difficulty: domain.Stage2Difficulty,
			RawAttack:        false,
			BypassAttack:     false,
			LastLogs:         []domains.DomainLog{},

			TotalRequests:    0,
			BypassedRequests: 0,

			PrevRequests: 0,
			PrevBypassed: 0,

			RequestsPerSecond:             0,
			RequestsBypassedPerSecond:     0,
			PeakRequestsPerSecond:         0,
			PeakRequestsBypassedPerSecond: 0,
			RequestLogger:                 []domains.RequestLog{},
		}
		firewall.Mutex.Unlock()
	}

	domains.DomainsMap.Store("debug", domains.DomainSettings{
		Name: "debug",
	})

	firewall.Mutex.Lock()
	domains.DomainsData["debug"] = domains.DomainData{
		Name:             "debug",
		Stage:            0,
		StageManuallySet: false,
		RawAttack:        false,
		BypassAttack:     false,
		BufferCooldown:   0,
		LastLogs:         []domains.DomainLog{},

		TotalRequests:    0,
		BypassedRequests: 0,

		PrevRequests: 0,
		PrevBypassed: 0,

		RequestsPerSecond:             0,
		RequestsBypassedPerSecond:     0,
		PeakRequestsPerSecond:         0,
		PeakRequestsBypassedPerSecond: 0,
		RequestLogger:                 []domains.RequestLog{},
	}

	firewall.Mutex.Unlock()

	vcErr := VersionCheck()
	if vcErr != nil {
		panic("[ " + utils.PrimaryColor("!") + " ] [ " + vcErr.Error() + " ]")
	}

	if len(domains.Domains) == 0 {
		AddDomain()
		Load()
	} else {
		proxy.WatchedDomain = domains.Domains[0]
	}
}

func VersionCheck() error {
	resp, err := http.Get("https://raw.githubusercontent.com/41Baloo/balooProxy/main/global/proxy/version.json")
	if err != nil {
		return errors.New("Failed to check for proxy version: " + err.Error())
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return errors.New("Failed to check for proxy version: " + err.Error())
	}

	var proxyVersions GLOBAL_PROXY_VERSIONS
	err = json.Unmarshal(body, &proxyVersions)
	if err != nil {
		return errors.New("Failed to check for proxy version: " + err.Error())
	}

	if proxyVersions.StableVersion > proxy.ProxyVersion {

		fmt.Println("[ " + utils.PrimaryColor("!") + " ] [ New Proxy Version " + fmt.Sprint(proxyVersions.StableVersion) + " Found. You Are using " + fmt.Sprint(proxy.ProxyVersion) + ". Consider Downloading The New Version From Github Or " + proxyVersions.Download + " ]")
		fmt.Println("[ " + utils.PrimaryColor("+") + " ] [ Automatically Starting Proxy In 10 Seconds ]")

		time.Sleep(10 * time.Second)

	}

	return nil
}
