package virustotal

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pterm/pterm"
)

var (
	cache    = make(map[string]VTResult)
	cacheMut sync.RWMutex

	disabled atomic.Bool

	// Rate limiting state
	lastRequestTime time.Time
	requestMut      sync.Mutex

	// API Limits (Free Tier)
	requestsPerMinute = 4
	minRequestDelay   = time.Minute / time.Duration(requestsPerMinute)
)

type VTResult struct {
	Malicious  int
	Undetected int
	Queried    bool
}

type VTResponse struct {
	Data struct {
		Attributes struct {
			LastAnalysisStats struct {
				Malicious  int `json:"malicious"`
				Undetected int `json:"undetected"`
			} `json:"last_analysis_stats"`
		} `json:"attributes"`
	} `json:"data"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

func CheckHash(apiKey, hash string) (VTResult, error) {
	if apiKey == "" {
		return VTResult{}, nil
	}
	if disabled.Load() {
		return VTResult{}, nil
	}

	// Check cache first
	cacheMut.RLock()
	if res, ok := cache[hash]; ok {
		cacheMut.RUnlock()
		return res, nil
	}
	cacheMut.RUnlock()

	// Rate limiting: Ensure we don't exceed 4 requests per minute
	requestMut.Lock()
	now := time.Now()
	timeSinceLastRequest := now.Sub(lastRequestTime)

	if timeSinceLastRequest < minRequestDelay {
		waitTime := minRequestDelay - timeSinceLastRequest
		pterm.Warning.Printf("VirusTotal API rate limit (4/min). Waiting %v before next request...\n", waitTime.Round(time.Second))
		time.Sleep(waitTime)
	}
	lastRequestTime = time.Now()
	requestMut.Unlock()

	url := fmt.Sprintf("https://www.virustotal.com/api/v3/files/%s", hash)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return VTResult{}, err
	}
	req.Header.Add("x-apikey", apiKey)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return VTResult{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		res := VTResult{Queried: true}
		cacheMut.Lock()
		cache[hash] = res
		cacheMut.Unlock()
		return res, nil
	}

	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == 429 {
		disabled.Store(true)
		pterm.Error.Println("VirusTotal API daily/monthly quota exceeded or rate limited. Skipping further VT checks for now.")
		return VTResult{}, fmt.Errorf("virustotal api quota exceeded (429)")
	}

	if resp.StatusCode != http.StatusOK {
		return VTResult{}, fmt.Errorf("virustotal api returned status: %d", resp.StatusCode)
	}

	var vtResp VTResponse
	if err := json.NewDecoder(resp.Body).Decode(&vtResp); err != nil {
		return VTResult{}, err
	}

	if vtResp.Error != nil {
		return VTResult{}, fmt.Errorf("virustotal error: %s", vtResp.Error.Message)
	}

	res := VTResult{
		Malicious:  vtResp.Data.Attributes.LastAnalysisStats.Malicious,
		Undetected: vtResp.Data.Attributes.LastAnalysisStats.Undetected,
		Queried:    true,
	}

	cacheMut.Lock()
	cache[hash] = res
	cacheMut.Unlock()

	return res, nil
}
