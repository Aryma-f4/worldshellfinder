package scanner

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"embed"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/Aryma-f4/worldshellfinder/internal/config"
	"sync"
	"sync/atomic"

	"github.com/Aryma-f4/worldshellfinder/internal/models"
	"github.com/Aryma-f4/worldshellfinder/internal/reporter"
	"github.com/Aryma-f4/worldshellfinder/internal/utils"
	"github.com/Aryma-f4/worldshellfinder/internal/virustotal"
	"github.com/pterm/pterm"
)

type scanIndicators struct {
	hasUserInput    bool
	commandExecHits int
	obfuscationHits int
	uploadHits      int
	fileWriteHits   int
	shellMarkerHits int
}

func LoadKeywords(wordlistPath string, defaultWordlist embed.FS) ([]string, error) {
	file, err := defaultWordlist.Open("wordlists/default.txt")
	if err != nil {
		return nil, err
	}
	defer file.Close()
	keywords, err := scanKeywordReader(file)
	if err != nil {
		return nil, err
	}

	if wordlistPath != "" {
		file2, err := os.Open(wordlistPath)
		if err != nil {
			return nil, err
		}
		defer file2.Close()
		extra, err := scanKeywordReader(file2)
		if err != nil {
			return nil, err
		}
		keywords = append(keywords, extra...)
	}

	seen := make(map[string]struct{}, len(keywords))
	deduped := make([]string, 0, len(keywords))
	for _, keyword := range keywords {
		normalized := strings.ToLower(strings.TrimSpace(keyword))
		if normalized == "" {
			continue
		}
		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		deduped = append(deduped, normalized)
	}

	return deduped, nil
}

func scanKeywordReader(r io.Reader) ([]string, error) {
	var keywords []string
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		keyword := strings.TrimSpace(scanner.Text())
		if keyword != "" {
			keywords = append(keywords, keyword)
		}
	}
	return keywords, scanner.Err()
}

func BuildDetectionRules() ([]models.DetectionRule, error) {
	ruleDefs := []struct {
		name    string
		pattern string
		weight  int
	}{
		{"user controlled command execution", `(?i)(?:system|exec|shell_exec|passthru|popen|proc_open|assert)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\s*\[`, 5},
		{"obfuscated eval chain", `(?i)(?:eval|assert)\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|str_rot13|rawurldecode|urldecode|strrev)\s*\(`, 5},
		{"encoded payload execution", `(?i)(?:eval|assert|system|exec|shell_exec|passthru)\s*\(\s*["'][A-Za-z0-9+/=]{40,}["']\s*\)`, 5},
		{"dynamic function invocation", `(?i)\$\w+\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[`, 4},
		{"php upload dropper", `(?i)move_uploaded_file\s*\(.*?\.ph(?:p|ar|tml|p\d)`, 4},
		{"preg replace eval modifier", `(?i)preg_replace\s*\(\s*['"][^'"]*/e[^'"]*['"]`, 4},
		{"runtime exec jsp", `(?i)Runtime\.getRuntime\(\)\.exec\s*\(`, 5},
		{"asp request eval", `(?i)(?:Execute|Eval)\s*\(\s*Request\.(?:Form|QueryString|Item)`, 5},
		{"process builder command", `(?i)ProcessBuilder\s*\(\s*(?:new\s+String\[\]|["'])`, 4},
		{"halt compiler payload", `(?i)__halt_compiler\s*\(`, 4},
		{"command parameter", `(?i)\$_(?:GET|POST|REQUEST)\s*\[\s*['"](?:cmd|exec|shell|command|payload)['"]\s*\]`, 3},
		{"upload form marker", `(?i)(?:multipart/form-data|type\s*=\s*["']file["'])`, 2},
	}

	rules := make([]models.DetectionRule, 0, len(ruleDefs))
	for _, def := range ruleDefs {
		rx, err := regexp.Compile(def.pattern)
		if err != nil {
			return nil, fmt.Errorf("compile rule %q: %w", def.name, err)
		}
		rules = append(rules, models.DetectionRule{
			Name:    def.name,
			Pattern: rx,
			Weight:  def.weight,
		})
	}

	return rules, nil
}

func BuildScanConfig(wordlistPath string, minScore, maxEvidence int, vtApiKey string, defaultWordlist embed.FS) (models.ScanConfig, error) {
	keywords, err := LoadKeywords(wordlistPath, defaultWordlist)
	if err != nil {
		return models.ScanConfig{}, fmt.Errorf("fail to load keywords: %w", err)
	}

	rules, err := BuildDetectionRules()
	if err != nil {
		return models.ScanConfig{}, fmt.Errorf("fail to build detection rules: %w", err)
	}

	return models.ScanConfig{
		Keywords:    keywords,
		Rules:       rules,
		MinScore:    minScore,
		MaxEvidence: maxEvidence,
		VTApiKey:    vtApiKey,
	}, nil
}

func ScanDirectory(directory string, cfg models.ScanConfig, verbose bool, numWorkers int) (*models.ScanSummary, error) {
	var detections []*models.ShellDetection
	var totalFilesScanned int32
	var mu sync.Mutex

	fileChan := make(chan string, 1000)
	var wg sync.WaitGroup

	if numWorkers <= 0 {
		numWorkers = 1
	}

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range fileChan {
				atomic.AddInt32(&totalFilesScanned, 1)
				if verbose {
					pterm.Info.Printf("Scanning: %s\n", path)
				}

				detection, err := analyzeFile(path, cfg)
				if err != nil {
					utils.LogReadIssue(path, err)
					continue
				}
				if detection != nil {
					mu.Lock()
					detections = append(detections, detection)
					mu.Unlock()
				}
			}
		}()
	}

	err := filepath.Walk(directory, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			utils.LogWalkIssue(path, walkErr)
			return nil
		}
		if info.IsDir() {
			return nil
		}

		fileChan <- path
		return nil
	})
	
	close(fileChan)
	wg.Wait()

	if err != nil {
		return nil, err
	}

	sort.Slice(detections, func(i, j int) bool {
		if detections[i].Score == detections[j].Score {
			return detections[i].Path < detections[j].Path
		}
		return detections[i].Score > detections[j].Score
	})

	return &models.ScanSummary{
		Detections:        detections,
		TotalFilesScanned: int(totalFilesScanned),
	}, nil
}

func shouldScanFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	if _, ok := config.SuspiciousExtensions[ext]; ok {
		return true
	}

	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()

	buffer := make([]byte, 8192)
	n, err := file.Read(buffer)
	if err != nil && err != io.EOF {
		return false
	}
	return utils.LooksLikeText(buffer[:n])
}

func analyzeFile(filename string, cfg models.ScanConfig) (*models.ShellDetection, error) {
	if !shouldScanFile(filename) {
		return nil, nil
	}

	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	detection, err := analyzeReader(filename, file, cfg)
	if err != nil {
		return nil, err
	}
	if detection != nil {
		detection.Path = filename
	}
	return detection, nil
}

func getFileHash(filename string) string {
	f, err := os.Open(filename)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

func analyzeReader(filename string, reader io.Reader, cfg models.ScanConfig) (*models.ShellDetection, error) {
	scanner := bufio.NewScanner(reader)
	buf := make([]byte, 1024*1024)
	scanner.Buffer(buf, 20*1024*1024)

	score := 0
	evidences := make([]models.ShellEvidence, 0, cfg.MaxEvidence)
	seen := make(map[string]struct{})
	indicators := scanIndicators{}
	lineNumber := 0

	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()
		lowerLine := strings.ToLower(line)
		updateIndicators(lowerLine, &indicators)

		for _, keyword := range cfg.Keywords {
			if !strings.Contains(lowerLine, keyword) {
				continue
			}
			key := "keyword:" + keyword
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			score += 4
			evidences = append(evidences, models.ShellEvidence{
				Kind:       "keyword",
				Name:       keyword,
				Weight:     4,
				LineNumber: lineNumber,
				Matched:    utils.ShortenEvidence(line),
			})
		}

		for _, rule := range cfg.Rules {
			if !rule.Pattern.MatchString(line) {
				continue
			}
			key := "rule:" + rule.Name
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			score += rule.Weight
			evidences = append(evidences, models.ShellEvidence{
				Kind:       "rule",
				Name:       rule.Name,
				Weight:     rule.Weight,
				LineNumber: lineNumber,
				Matched:    utils.ShortenEvidence(line),
			})
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	score, evidences = addHeuristicEvidence(score, evidences, indicators, seen)

	// VirusTotal Integration
	if cfg.VTApiKey != "" && score > 0 {
		hash := getFileHash(filename)
		if hash != "" {
			vtRes, err := virustotal.CheckHash(cfg.VTApiKey, hash)
			if err == nil && vtRes.Queried && vtRes.Malicious > 0 {
				score += 10
				evidences = append(evidences, models.ShellEvidence{
					Kind:       "virustotal",
					Name:       fmt.Sprintf("VirusTotal flagged as malicious (%d positives)", vtRes.Malicious),
					Weight:     10,
					LineNumber: 0,
					Matched:    "File hash found in VirusTotal malware database",
				})
			}
		}
	}

	if score < cfg.MinScore {
		return nil, nil
	}

	sort.Slice(evidences, func(i, j int) bool {
		if evidences[i].Weight == evidences[j].Weight {
			return evidences[i].LineNumber < evidences[j].LineNumber
		}
		return evidences[i].Weight > evidences[j].Weight
	})

	maxEvidence := cfg.MaxEvidence
	if maxEvidence <= 0 {
		maxEvidence = config.DefaultMaxEvidence
	}
	if len(evidences) > maxEvidence {
		evidences = evidences[:maxEvidence]
	}

	return &models.ShellDetection{
		Path:      filename,
		Score:     score,
		Evidences: evidences,
	}, nil
}

func addHeuristicEvidence(score int, evidences []models.ShellEvidence, indicators scanIndicators, seen map[string]struct{}) (int, []models.ShellEvidence) {
	type heuristic struct {
		key     string
		name    string
		weight  int
		matched string
		enabled bool
	}

	heuristics := []heuristic{
		{
			key:     "heuristic:user-input-exec",
			name:    "user input combined with command execution",
			weight:  4,
			matched: "File combines request variables with command execution primitives.",
			enabled: indicators.hasUserInput && indicators.commandExecHits > 0,
		},
		{
			key:     "heuristic:obfuscated-exec",
			name:    "obfuscation combined with execution",
			weight:  4,
			matched: "File combines obfuscation helpers with execution functions.",
			enabled: indicators.obfuscationHits > 0 && indicators.commandExecHits > 0,
		},
		{
			key:     "heuristic:upload-dropper",
			name:    "upload flow combined with file write",
			weight:  3,
			matched: "File mixes upload handling with file creation or overwrite functions.",
			enabled: indicators.uploadHits > 0 && indicators.fileWriteHits > 0,
		},
		{
			key:     "heuristic:shell-ui",
			name:    "interactive shell markers",
			weight:  3,
			matched: "File contains shell-like UI markers plus execution-related code.",
			enabled: indicators.shellMarkerHits > 0 && indicators.commandExecHits > 0,
		},
	}

	for _, item := range heuristics {
		if !item.enabled {
			continue
		}
		if _, exists := seen[item.key]; exists {
			continue
		}
		seen[item.key] = struct{}{}
		score += item.weight
		evidences = append(evidences, models.ShellEvidence{
			Kind:       "heuristic",
			Name:       item.name,
			Weight:     item.weight,
			LineNumber: 0,
			Matched:    item.matched,
		})
	}

	return score, evidences
}

func updateIndicators(line string, indicators *scanIndicators) {
	if strings.Contains(line, "$_get[") || strings.Contains(line, "$_post[") || strings.Contains(line, "$_request[") || strings.Contains(line, "$_cookie[") || strings.Contains(line, "$_files[") || strings.Contains(line, "request.form") || strings.Contains(line, "request.querystring") {
		indicators.hasUserInput = true
	}
	if utils.ContainsAny(line, "system(", "exec(", "shell_exec(", "passthru(", "popen(", "proc_open(", "runtime.getruntime().exec", "processbuilder(") {
		indicators.commandExecHits++
	}
	if utils.ContainsAny(line, "base64_decode(", "gzinflate(", "gzuncompress(", "str_rot13(", "urldecode(", "rawurldecode(", "strrev(", "fromcharcode(", "base64.b64decode(") {
		indicators.obfuscationHits++
	}
	if utils.ContainsAny(line, "move_uploaded_file(", "$_files[", "multipart/form-data", "type=\"file\"", "type='file'") {
		indicators.uploadHits++
	}
	if utils.ContainsAny(line, "file_put_contents(", "fopen(", "fwrite(", "copy(", "chmod(", "touch(", "move_uploaded_file(") {
		indicators.fileWriteHits++
	}
	if utils.ContainsAny(line, "cmd", "shell", "terminal", "upload", "file manager", "wso", "b374k", "c99") {
		indicators.shellMarkerHits++
	}
}

func RunDetection(directory, wordlistPath, outputFile string, minScore, maxEvidence int, vtApiKey string, verbose bool, defaultWordlist embed.FS, numWorkers int) error {
	cfg, err := BuildScanConfig(wordlistPath, minScore, maxEvidence, vtApiKey, defaultWordlist)
	if err != nil {
		return err
	}

	done := make(chan bool)
	go utils.LoadingAnimation(done)
	summary, err := ScanDirectory(directory, cfg, verbose, numWorkers)
	done <- true
	if err != nil {
		return err
	}

	reporter.PrintDetectionSummary(summary, verbose)
	if outputFile != "" {
		if err := reporter.WriteDetectionsToFile(outputFile, summary); err != nil {
			return fmt.Errorf("error writing to output file: %w", err)
		}
		pterm.Success.Printf("Results have been saved to: %s\n", outputFile)
	}
	return nil
}
