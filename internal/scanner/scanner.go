package scanner

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/Aryma-f4/worldshellfinder/internal/config"
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

func LoadKeywords(wordlistPath string, defaultWordlist embed.FS) ([]models.KeywordRule, error) {
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
	var deduped []models.KeywordRule
	for _, keyword := range keywords {
		normalized := strings.ToLower(strings.TrimSpace(keyword.Word))
		if normalized == "" {
			continue
		}
		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		deduped = append(deduped, models.KeywordRule{Word: normalized, Weight: keyword.Weight})
	}

	return deduped, nil
}

func scanKeywordReader(r io.Reader) ([]models.KeywordRule, error) {
	var keywords []models.KeywordRule
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "::", 2)
		word := parts[0]
		weight := 4 // Default weight for legacy lists
		if len(parts) == 2 {
			if w, err := strconv.Atoi(strings.TrimSpace(parts[1])); err == nil {
				weight = w
			}
		}
		if word != "" {
			keywords = append(keywords, models.KeywordRule{Word: word, Weight: weight})
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

func ScanDirectories(directories []string, cfg models.ScanConfig, verbose bool, numWorkers int) (*models.ScanSummary, error) {
	var detections []*models.ShellDetection
	var totalFilesScanned int32
	var mu sync.Mutex
	var printMu sync.Mutex

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
					printMu.Lock()
					reporter.PrintSingleDetection(detection, verbose)
					printMu.Unlock()
					mu.Lock()
					detections = append(detections, detection)
					mu.Unlock()
				}
			}
		}()
	}

	for _, directory := range directories {
		directory = strings.TrimSpace(directory)
		if directory == "" {
			continue
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
		if err != nil {
			utils.LogWalkIssue(directory, err)
			continue
		}
	}

	close(fileChan)
	wg.Wait()

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

	info, err := os.Stat(path)
	if err != nil {
		return false
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
	sample := buffer[:n]
	if utils.LooksLikeText(sample) {
		return true
	}
	if info.Mode()&0111 != 0 {
		return true
	}
	return binaryFormat(sample) != ""
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

	buffer := make([]byte, 8192)
	n, err := file.Read(buffer)
	if err != nil {
		return nil, err
	}
	reader := io.MultiReader(bytes.NewReader(buffer[:n]), file)

	var detection *models.ShellDetection
	if utils.LooksLikeText(buffer[:n]) {
		detection, err = analyzeReader(filename, reader, cfg)
	} else {
		detection, err = analyzeBinaryReader(filename, reader, cfg, buffer[:n])
	}
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

var (
	binaryURLRx    = regexp.MustCompile(`(?i)https?://[^\s"'\\]+`)
	binaryIPPortRx = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}:\d{2,5}\b`)
	binaryDomainRx = regexp.MustCompile(`(?i)\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b`)
)

func binaryFormat(sample []byte) string {
	if len(sample) < 4 {
		return ""
	}
	if len(sample) >= 4 && sample[0] == 0x7f && sample[1] == 'E' && sample[2] == 'L' && sample[3] == 'F' {
		return "ELF"
	}
	if len(sample) >= 2 && sample[0] == 'M' && sample[1] == 'Z' {
		return "PE"
	}
	if len(sample) >= 4 {
		magic := uint32(sample[0])<<24 | uint32(sample[1])<<16 | uint32(sample[2])<<8 | uint32(sample[3])
		switch magic {
		case 0xFEEDFACE, 0xFEEDFACF, 0xCEFAEDFE, 0xCFFAEDFE:
			return "Mach-O"
		case 0xCAFEBABE, 0xBEBAFECA:
			return "Mach-O Fat"
		}
	}
	return ""
}

func applyVirusTotal(apiKey, filename string, score *int, evidences *[]models.ShellEvidence) {
	if apiKey == "" {
		return
	}
	if *score < 8 {
		return
	}
	hash := getFileHash(filename)
	if hash == "" {
		return
	}
	vtRes, err := virustotal.CheckHash(apiKey, hash)
	if err != nil {
		return
	}
	if vtRes.Queried && vtRes.Malicious > 0 {
		*score += 10
		*evidences = append(*evidences, models.ShellEvidence{
			Kind:       "virustotal",
			Name:       fmt.Sprintf("VirusTotal flagged as malicious (%d positives)", vtRes.Malicious),
			Weight:     10,
			LineNumber: 0,
			Matched:    "File hash found in VirusTotal malware database",
		})
	}
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
			if !strings.Contains(lowerLine, keyword.Word) {
				continue
			}
			key := "keyword:" + keyword.Word
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			score += keyword.Weight
			evidences = append(evidences, models.ShellEvidence{
				Kind:       "keyword",
				Name:       keyword.Word,
				Weight:     keyword.Weight,
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
	applyVirusTotal(cfg.VTApiKey, filename, &score, &evidences)

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

func analyzeBinaryReader(filename string, reader io.Reader, cfg models.ScanConfig, header []byte) (*models.ShellDetection, error) {
	const maxBinaryBytes = 20 * 1024 * 1024
	const minStringLen = 6
	const maxEvidenceHits = 64

	data, err := io.ReadAll(io.LimitReader(reader, maxBinaryBytes))
	if err != nil {
		return nil, err
	}

	score := 0
	evidences := make([]models.ShellEvidence, 0, cfg.MaxEvidence)
	seen := make(map[string]struct{})

	format := binaryFormat(header)
	if format != "" {
		score += 2
		evidences = append(evidences, models.ShellEvidence{
			Kind:       "binary",
			Name:       "executable format",
			Weight:     2,
			LineNumber: 0,
			Matched:    format,
		})
	}

	networkAPIHits := 0
	urlHits := 0
	ipPortHits := 0
	domainHits := 0
	c2Hits := 0
	injectHits := 0
	persistHits := 0
	packerHits := 0

	networkAPIs := []string{
		"wsastartup", "ws2_32", "wininet", "winhttp", "internetopen", "internetconnect", "httpopenrequest", "winhttpreceive", "winhttpsend",
		"socket", "connect", "recv", "send", "getaddrinfo", "gethostbyname", "dnsquery", "libcurl", "curl_easy", "curl_multi",
		"cfnetwork", "nsurlsession", "urlsession", "cfsocket", "scnetworkreachability",
		"net/http", "httpclient", "user-agent", "content-type", "authorization:",
	}

	c2Markers := []string{
		"mythic", "apollo", "poseidon", "beacon", "callback", "tasking", "c2", "agent", "implant",
		"sliver", "metasploit", "empire", "cobalt strike", "havoc", "bruteratel",
	}

	injectMarkers := []string{
		"virtualalloc", "virtualprotect", "writeprocessmemory", "createremotethread", "ntcreatethreadex", "queueuserapc",
		"rtlmovememory", "loadlibrary", "getprocaddress", "ntdll.dll",
	}

	persistMarkers := []string{
		"schtasks", "reg add", "run\\", "runonce", "startup", "launchctl", "launchagents", "launchdaemons", "systemctl", "crontab", "rc.local",
	}

	packerMarkers := []string{
		"upx!", "themida", "vmprotect", "mpress", "aspack",
	}

	current := make([]byte, 0, 256)
	flush := func() {
		if len(current) < minStringLen {
			current = current[:0]
			return
		}
		s := strings.ToLower(string(current))
		current = current[:0]

		if len(seen) > maxEvidenceHits {
			return
		}

		for _, needle := range networkAPIs {
			if strings.Contains(s, needle) {
				key := "bin:net:" + needle
				if _, ok := seen[key]; !ok {
					seen[key] = struct{}{}
					score += 3
					networkAPIHits++
					evidences = append(evidences, models.ShellEvidence{
						Kind:       "binary",
						Name:       "network indicator",
						Weight:     3,
						LineNumber: 0,
						Matched:    needle,
					})
				}
			}
		}

		for _, needle := range c2Markers {
			if strings.Contains(s, needle) {
				key := "bin:c2:" + needle
				if _, ok := seen[key]; !ok {
					seen[key] = struct{}{}
					score += 4
					c2Hits++
					evidences = append(evidences, models.ShellEvidence{
						Kind:       "binary",
						Name:       "c2 marker",
						Weight:     4,
						LineNumber: 0,
						Matched:    needle,
					})
				}
			}
		}

		for _, needle := range injectMarkers {
			if strings.Contains(s, needle) {
				key := "bin:inj:" + needle
				if _, ok := seen[key]; !ok {
					seen[key] = struct{}{}
					score += 5
					injectHits++
					evidences = append(evidences, models.ShellEvidence{
						Kind:       "binary",
						Name:       "process injection indicator",
						Weight:     5,
						LineNumber: 0,
						Matched:    needle,
					})
				}
			}
		}

		for _, needle := range persistMarkers {
			if strings.Contains(s, needle) {
				key := "bin:pers:" + needle
				if _, ok := seen[key]; !ok {
					seen[key] = struct{}{}
					score += 4
					persistHits++
					evidences = append(evidences, models.ShellEvidence{
						Kind:       "binary",
						Name:       "persistence indicator",
						Weight:     4,
						LineNumber: 0,
						Matched:    needle,
					})
				}
			}
		}

		for _, needle := range packerMarkers {
			if strings.Contains(s, needle) {
				key := "bin:pack:" + needle
				if _, ok := seen[key]; !ok {
					seen[key] = struct{}{}
					score += 3
					packerHits++
					evidences = append(evidences, models.ShellEvidence{
						Kind:       "binary",
						Name:       "packer indicator",
						Weight:     3,
						LineNumber: 0,
						Matched:    needle,
					})
				}
			}
		}

		for _, keyword := range cfg.Keywords {
			if strings.Contains(s, keyword.Word) {
				key := "bin:kw:" + keyword.Word
				if _, ok := seen[key]; !ok {
					seen[key] = struct{}{}
					score += keyword.Weight
					evidences = append(evidences, models.ShellEvidence{
						Kind:       "keyword",
						Name:       keyword.Word,
						Weight:     keyword.Weight,
						LineNumber: 0,
						Matched:    s,
					})
				}
			}
		}

		if binaryURLRx.MatchString(s) {
			key := "bin:url"
			if _, ok := seen[key]; !ok {
				seen[key] = struct{}{}
				score += 5
				urlHits++
				evidences = append(evidences, models.ShellEvidence{
					Kind:       "binary",
					Name:       "hardcoded url",
					Weight:     5,
					LineNumber: 0,
					Matched:    utils.ShortenEvidence(s),
				})
			}
		}

		if binaryIPPortRx.MatchString(s) {
			key := "bin:ipport"
			if _, ok := seen[key]; !ok {
				seen[key] = struct{}{}
				score += 4
				ipPortHits++
				evidences = append(evidences, models.ShellEvidence{
					Kind:       "binary",
					Name:       "hardcoded ip:port",
					Weight:     4,
					LineNumber: 0,
					Matched:    utils.ShortenEvidence(s),
				})
			}
		}

		if binaryDomainRx.MatchString(s) {
			domainHits++
		}
	}

	for _, b := range data {
		if (b >= 32 && b <= 126) || b == '\t' {
			if len(current) < 4096 {
				current = append(current, b)
			}
			continue
		}
		flush()
	}
	flush()

	if networkAPIHits > 0 && (urlHits > 0 || ipPortHits > 0 || domainHits > 5) {
		key := "bin:heur:net"
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
			score += 5
			evidences = append(evidences, models.ShellEvidence{
				Kind:       "heuristic",
				Name:       "binary contains networking indicators typical for C2/backdoor",
				Weight:     5,
				LineNumber: 0,
				Matched:    "Networking APIs combined with hardcoded endpoints or domains.",
			})
		}
	}

	if (injectHits > 0 || persistHits > 0) && networkAPIHits > 0 {
		key := "bin:heur:beh"
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
			score += 5
			evidences = append(evidences, models.ShellEvidence{
				Kind:       "heuristic",
				Name:       "binary contains malware-like behavior indicators",
				Weight:     5,
				LineNumber: 0,
				Matched:    "Network indicators combined with persistence or injection markers.",
			})
		}
	}

	if packerHits > 0 && networkAPIHits > 0 {
		key := "bin:heur:pack"
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
			score += 3
			evidences = append(evidences, models.ShellEvidence{
				Kind:       "heuristic",
				Name:       "packed binary with networking indicators",
				Weight:     3,
				LineNumber: 0,
				Matched:    "Packer strings combined with networking-related strings.",
			})
		}
	}

	applyVirusTotal(cfg.VTApiKey, filename, &score, &evidences)

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

func RunDetection(directories []string, wordlistPath, outputFile string, minScore, maxEvidence int, vtApiKey string, verbose bool, defaultWordlist embed.FS, numWorkers int) error {
	cfg, err := BuildScanConfig(wordlistPath, minScore, maxEvidence, vtApiKey, defaultWordlist)
	if err != nil {
		return err
	}

	done := make(chan bool)
	go utils.LoadingAnimation(done)
	summary, err := ScanDirectories(directories, cfg, verbose, numWorkers)
	done <- true
	fmt.Print("\rOperation complete!                          \n")
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
