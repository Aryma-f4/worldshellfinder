package virustotal

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

var cache = make(map[string]VTResult)

type VTResult struct {
	Malicious int
	Undetected int
	Queried   bool
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

	if res, ok := cache[hash]; ok {
		return res, nil
	}

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
		cache[hash] = res
		return res, nil
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
	cache[hash] = res
	return res, nil
}
