package main

import (
	"bufio"
	"bytes"
	"embed"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	Reset   = "\033[0m"
	Red     = "\033[31m"
	Green   = "\033[32m"
	Yellow  = "\033[33m"
	Blue    = "\033[34m"
	Magenta = "\033[35m"
	Cyan    = "\033[36m"
	White   = "\033[37m"
)

const defaultMinScore = 4
const defaultMaxEvidence = 5
const rootPermissionWarning = "not enough permission to do this, gotta root"

type FileModification struct {
	path           string
	originalSize   int64
	modifiedSize   int64
	stringsRemoved int
}

type DetectionRule struct {
	Name    string
	Pattern *regexp.Regexp
	Weight  int
}

type ShellEvidence struct {
	Kind       string
	Name       string
	Weight     int
	LineNumber int
	Matched    string
}

type ShellDetection struct {
	path      string
	score     int
	evidences []ShellEvidence
}

type ScanConfig struct {
	Keywords    []string
	Rules       []DetectionRule
	MinScore    int
	MaxEvidence int
}

type ScanSummary struct {
	detections        []*ShellDetection
	totalFilesScanned int
}

type SystemFinding struct {
	Category string
	Severity string
	Title    string
	Detail   string
}

type DeepScanSummary struct {
	FileSummary     *ScanSummary
	TrafficFindings []SystemFinding
	LogFindings     []SystemFinding
	RootkitFindings []SystemFinding
	Warnings        []string
}

type scanIndicators struct {
	hasUserInput    bool
	commandExecHits int
	obfuscationHits int
	uploadHits      int
	fileWriteHits   int
	shellMarkerHits int
}

//go:embed wordlists/default.txt
var defaultWordlist embed.FS

var verbose bool

var suspiciousExtensions = map[string]struct{}{
	".php":   {},
	".phtml": {},
	".php3":  {},
	".php4":  {},
	".php5":  {},
	".phar":  {},
	".inc":   {},
	".asp":   {},
	".aspx":  {},
	".ashx":  {},
	".jsp":   {},
	".jspx":  {},
	".cfm":   {},
	".cgi":   {},
	".pl":    {},
	".py":    {},
	".sh":    {},
}

const banner = `
` + Red + `
===========================================================================================
` + Cyan + `
 _    _            _     _ _____ _          _ _  ______ _           _           
| |  | |          | |   | /  ___| |        | | | |  ___(_)         | |          
| |  | | ___  _ __| | __| \ ` + "`" + `--.| |__   ___| | | | |_   _ _ __   __| | ___ _ __ 
| |/\| |/ _ \| '__| |/ _` + "`" + ` |` + "`" + `--. \ '_ \ / _ \ | | |  _| | | '_ \ / _` + "`" + ` |/ _ \ '__|
\  /\  / (_) | |  | | (_| /\__/ / | | |  __/ | | | |   | | | | | (_| |  __/ |   
 \/  \/ \___/|_|  |_|\__,_\____/|_| |_|\___|_|_| \_|   |_|_| |_|\__,_|\___|_|  
 ` + Reset + `
 made with love by ` + Yellow + ` Worldsavior/Aryma-f4 ` + Magenta + `^^	 ` + Green + `	v.2.1.0 Stable Build  ` + Reset + `
===========================================================================================
`

const menuText = `
Please choose an option:
1. Normal WebShell Detection
2. Remove String from Files
3. Deep Scan (files, traffic, rootkit)
`

func loadingAnimation(done chan bool) {
	chars := []rune{'|', '/', '-', '\\'}
	for {
		select {
		case <-done:
			fmt.Print("\rOperation complete!                          \n")
			return
		default:
			for _, c := range chars {
				fmt.Printf("\rProcessing... %c", c)
				time.Sleep(100 * time.Millisecond)
			}
		}
	}
}

func printHelp() {
	fmt.Println("Usage:")
	fmt.Println("  worldshellfinder -mode detect -dir <directory> [options]")
	fmt.Println("  worldshellfinder -mode deep -dir <directory> [options]")
	fmt.Println("  worldshellfinder -mode remove -dir <directory> -remove-string <value> [options]")
	fmt.Println("  worldshellfinder")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  -h, --help              Show help information")
	fmt.Println("  -v                      Enable verbose output")
	fmt.Println("  -mode string            Operation mode: detect, deep, or remove")
	fmt.Println("  -dir string             Directory to scan")
	fmt.Println("  -out string             Output file path")
	fmt.Println("  -wordlist string        Additional custom wordlist file")
	fmt.Println("  -min-score int          Minimum score before a file is reported (default: 4)")
	fmt.Println("  -max-evidence int       Maximum evidence entries shown per file (default: 5)")
	fmt.Println("  -remove-string string   String to remove when mode=remove")
	fmt.Println("  --update                Update to the latest release")
}

func updateFromRepository(repoURL string) error {
	osType := runtime.GOOS
	archType := runtime.GOARCH
	downloadURL := fmt.Sprintf("https://%s/releases/latest/download/%s_%s", repoURL, osType, archType)
	fmt.Printf("Downloading update from: %s\n", downloadURL)

	tmpFile, err := os.CreateTemp("", "worldshellfinder_*")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	defer tmpFile.Close()

	resp, err := http.Get(downloadURL)
	if err != nil {
		return fmt.Errorf("failed to download update: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download update: HTTP %d", resp.StatusCode)
	}

	if _, err = io.Copy(tmpFile, resp.Body); err != nil {
		return fmt.Errorf("failed to write update to file: %w", err)
	}

	executablePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get current executable path: %w", err)
	}

	if err = os.Rename(tmpFile.Name(), executablePath); err != nil {
		return fmt.Errorf("failed to replace current binary: %w", err)
	}

	if err = os.Chmod(executablePath, 0755); err != nil {
		return fmt.Errorf("failed to make new binary executable: %w", err)
	}

	fmt.Println("Update complete! Restarting the application...")

	cmd := exec.Command(executablePath)
	if err = cmd.Start(); err != nil {
		return fmt.Errorf("failed to restart application: %w", err)
	}
	os.Exit(0)
	return nil
}

func removeStringFromFile(filePath string, stringToRemove string) (*FileModification, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	originalSize := int64(len(content))
	originalContent := string(content)
	stringsRemoved := strings.Count(originalContent, stringToRemove)
	if stringsRemoved == 0 {
		return nil, nil
	}

	newContent := strings.ReplaceAll(originalContent, stringToRemove, "")
	if err = os.WriteFile(filePath, []byte(newContent), 0644); err != nil {
		return nil, err
	}

	return &FileModification{
		path:           filePath,
		originalSize:   originalSize,
		modifiedSize:   int64(len(newContent)),
		stringsRemoved: stringsRemoved,
	}, nil
}

func loadKeywords(wordlistPath string) ([]string, error) {
	keywords, err := readKeywordFileFromEmbed("wordlists/default.txt")
	if err != nil {
		return nil, err
	}

	if wordlistPath != "" {
		extra, err := readKeywordFile(wordlistPath)
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

func readKeywordFileFromEmbed(path string) ([]string, error) {
	file, err := defaultWordlist.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return scanKeywordReader(file)
}

func readKeywordFile(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return scanKeywordReader(file)
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

func buildDetectionRules() ([]DetectionRule, error) {
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

	rules := make([]DetectionRule, 0, len(ruleDefs))
	for _, def := range ruleDefs {
		rx, err := regexp.Compile(def.pattern)
		if err != nil {
			return nil, fmt.Errorf("compile rule %q: %w", def.name, err)
		}
		rules = append(rules, DetectionRule{
			Name:    def.name,
			Pattern: rx,
			Weight:  def.weight,
		})
	}

	return rules, nil
}

func scanDirectory(directory string, cfg ScanConfig) (*ScanSummary, error) {
	var detections []*ShellDetection
	totalFilesScanned := 0

	err := filepath.Walk(directory, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			logWalkIssue(path, walkErr)
			return nil
		}
		if info.IsDir() {
			return nil
		}

		totalFilesScanned++
		if verbose {
			fmt.Printf("\rScanning: %s", path)
		}

		detection, err := analyzeFile(path, cfg)
		if err != nil {
			logReadIssue(path, err)
			return nil
		}
		if detection != nil {
			detections = append(detections, detection)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	sort.Slice(detections, func(i, j int) bool {
		if detections[i].score == detections[j].score {
			return detections[i].path < detections[j].path
		}
		return detections[i].score > detections[j].score
	})

	if verbose {
		fmt.Print("\r")
	}

	return &ScanSummary{
		detections:        detections,
		totalFilesScanned: totalFilesScanned,
	}, nil
}

func analyzeFile(filename string, cfg ScanConfig) (*ShellDetection, error) {
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
		detection.path = filename
	}
	return detection, nil
}

func analyzeReader(filename string, reader io.Reader, cfg ScanConfig) (*ShellDetection, error) {
	scanner := bufio.NewScanner(reader)
	buf := make([]byte, 1024*1024)
	scanner.Buffer(buf, 20*1024*1024)

	score := 0
	evidences := make([]ShellEvidence, 0, cfg.MaxEvidence)
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
			evidences = append(evidences, ShellEvidence{
				Kind:       "keyword",
				Name:       keyword,
				Weight:     4,
				LineNumber: lineNumber,
				Matched:    shortenEvidence(line),
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
			evidences = append(evidences, ShellEvidence{
				Kind:       "rule",
				Name:       rule.Name,
				Weight:     rule.Weight,
				LineNumber: lineNumber,
				Matched:    shortenEvidence(line),
			})
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	score, evidences = addHeuristicEvidence(score, evidences, indicators, seen)
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
		maxEvidence = defaultMaxEvidence
	}
	if len(evidences) > maxEvidence {
		evidences = evidences[:maxEvidence]
	}

	return &ShellDetection{
		path:      filename,
		score:     score,
		evidences: evidences,
	}, nil
}

func addHeuristicEvidence(score int, evidences []ShellEvidence, indicators scanIndicators, seen map[string]struct{}) (int, []ShellEvidence) {
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
		evidences = append(evidences, ShellEvidence{
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
	if containsAny(line, "system(", "exec(", "shell_exec(", "passthru(", "popen(", "proc_open(", "runtime.getruntime().exec", "processbuilder(") {
		indicators.commandExecHits++
	}
	if containsAny(line, "base64_decode(", "gzinflate(", "gzuncompress(", "str_rot13(", "urldecode(", "rawurldecode(", "strrev(", "fromcharcode(", "base64.b64decode(") {
		indicators.obfuscationHits++
	}
	if containsAny(line, "move_uploaded_file(", "$_files[", "multipart/form-data", "type=\"file\"", "type='file'") {
		indicators.uploadHits++
	}
	if containsAny(line, "file_put_contents(", "fopen(", "fwrite(", "copy(", "chmod(", "touch(", "move_uploaded_file(") {
		indicators.fileWriteHits++
	}
	if containsAny(line, "cmd", "shell", "terminal", "upload", "file manager", "wso", "b374k", "c99") {
		indicators.shellMarkerHits++
	}
}

func containsAny(line string, patterns ...string) bool {
	for _, pattern := range patterns {
		if strings.Contains(line, pattern) {
			return true
		}
	}
	return false
}

func shouldScanFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	if _, ok := suspiciousExtensions[ext]; ok {
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
	return looksLikeText(buffer[:n])
}

func looksLikeText(sample []byte) bool {
	if len(sample) == 0 {
		return true
	}
	if bytes.Contains(sample, []byte("<?php")) || bytes.Contains(sample, []byte("<%")) || bytes.Contains(sample, []byte("<?=")) {
		return true
	}
	if bytes.IndexByte(sample, 0) >= 0 {
		return false
	}
	if !utf8.Valid(sample) {
		return false
	}

	printable := 0
	for _, b := range sample {
		if b == '\n' || b == '\r' || b == '\t' || (b >= 32 && b <= 126) {
			printable++
		}
	}
	return float64(printable)/float64(len(sample)) >= 0.75
}

func shortenEvidence(line string) string {
	clean := strings.TrimSpace(line)
	if len(clean) <= 180 {
		return clean
	}
	return clean[:177] + "..."
}

func printDetectionSummary(summary *ScanSummary) {
	fmt.Printf("\n%sWebShell Detection Summary:%s\n", Yellow, Reset)
	fmt.Printf("Total files scanned: %d\n", summary.totalFilesScanned)
	fmt.Printf("Total potential webshells found: %d\n", len(summary.detections))

	if len(summary.detections) == 0 {
		fmt.Printf("\n%sNo potential webshells were found.%s\n", Green, Reset)
		return
	}

	fmt.Printf("\n%sPotential WebShells Found:%s\n", Red, Reset)
	for _, detect := range summary.detections {
		fmt.Printf("\n- File: %s\n", detect.path)
		fmt.Printf("  Suspicion score: %d\n", detect.score)
		for _, evidence := range detect.evidences {
			if evidence.LineNumber > 0 {
				fmt.Printf("  Evidence [%s] line %d (+%d): %s\n", evidence.Kind, evidence.LineNumber, evidence.Weight, evidence.Name)
			} else {
				fmt.Printf("  Evidence [%s] (+%d): %s\n", evidence.Kind, evidence.Weight, evidence.Name)
			}
			if verbose && evidence.Matched != "" {
				fmt.Printf("    -> %s\n", evidence.Matched)
			}
		}
	}
}

func writeDetectionsToFile(path string, summary *ScanSummary) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	fmt.Fprintln(writer, "WebShell Detection Report")
	fmt.Fprintf(writer, "Generated: %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Fprintf(writer, "Total files scanned: %d\n", summary.totalFilesScanned)
	fmt.Fprintf(writer, "Total potential webshells found: %d\n\n", len(summary.detections))

	for i, detect := range summary.detections {
		fmt.Fprintf(writer, "Detection #%d:\n", i+1)
		fmt.Fprintf(writer, "- File: %s\n", detect.path)
		fmt.Fprintf(writer, "- Suspicion score: %d\n", detect.score)
		for _, evidence := range detect.evidences {
			if evidence.LineNumber > 0 {
				fmt.Fprintf(writer, "- Evidence [%s] line %d (+%d): %s\n", evidence.Kind, evidence.LineNumber, evidence.Weight, evidence.Name)
			} else {
				fmt.Fprintf(writer, "- Evidence [%s] (+%d): %s\n", evidence.Kind, evidence.Weight, evidence.Name)
			}
			if evidence.Matched != "" {
				fmt.Fprintf(writer, "  Matched text: %s\n", evidence.Matched)
			}
		}
		fmt.Fprintln(writer)
	}

	return writer.Flush()
}

func writeModificationsToFile(filepath string, modifications []*FileModification, totalFilesScanned int, totalStringsRemoved int) error {
	file, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	fmt.Fprintf(writer, "String Removal Report\n")
	fmt.Fprintf(writer, "Generated: %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Fprintf(writer, "Total files scanned: %d\n", totalFilesScanned)
	fmt.Fprintf(writer, "Total files modified: %d\n", len(modifications))
	fmt.Fprintf(writer, "Total strings removed: %d\n\n", totalStringsRemoved)

	for i, mod := range modifications {
		fmt.Fprintf(writer, "Modification #%d:\n", i+1)
		fmt.Fprintf(writer, "- File: %s\n", mod.path)
		fmt.Fprintf(writer, "- Strings removed: %d\n", mod.stringsRemoved)
		fmt.Fprintf(writer, "- Original size: %d bytes\n", mod.originalSize)
		fmt.Fprintf(writer, "- Modified size: %d bytes\n", mod.modifiedSize)
		fmt.Fprintf(writer, "- Size difference: %d bytes\n\n", mod.originalSize-mod.modifiedSize)
	}

	return writer.Flush()
}

func buildScanConfig(wordlistPath string, minScore, maxEvidence int) (ScanConfig, error) {
	keywords, err := loadKeywords(wordlistPath)
	if err != nil {
		return ScanConfig{}, fmt.Errorf("fail to load keywords: %w", err)
	}

	rules, err := buildDetectionRules()
	if err != nil {
		return ScanConfig{}, fmt.Errorf("fail to build detection rules: %w", err)
	}

	return ScanConfig{
		Keywords:    keywords,
		Rules:       rules,
		MinScore:    minScore,
		MaxEvidence: maxEvidence,
	}, nil
}

func isPermissionIssue(err error) bool {
	if err == nil {
		return false
	}
	if os.IsPermission(err) {
		return true
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "permission denied") || strings.Contains(message, "operation not permitted")
}

func permissionWarningFor(path string) string {
	if path == "" {
		return rootPermissionWarning
	}
	return fmt.Sprintf("%s (%s)", rootPermissionWarning, path)
}

func logWalkIssue(path string, err error) {
	if isPermissionIssue(err) {
		log.Printf("%s\n", permissionWarningFor(path))
		return
	}
	log.Printf("Error accessing file or directory %s: %v\n", path, err)
}

func logReadIssue(path string, err error) {
	if isPermissionIssue(err) {
		log.Printf("%s\n", permissionWarningFor(path))
		return
	}
	log.Printf("Error reading file %s: %v\n", path, err)
}

func appendUnique(values []string, value string) []string {
	if slices.Contains(values, value) {
		return values
	}
	return append(values, value)
}

func newFinding(category, severity, title, detail string) SystemFinding {
	return SystemFinding{
		Category: category,
		Severity: severity,
		Title:    title,
		Detail:   detail,
	}
}

func currentUserIsRoot() bool {
	if runtime.GOOS == "windows" {
		return false
	}
	output, err := exec.Command("id", "-u").Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(output)) == "0"
}

func commandAvailable(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func runCommandOutput(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		trimmed := strings.TrimSpace(string(output))
		if trimmed == "" {
			return "", err
		}
		return trimmed, fmt.Errorf("%w: %s", err, trimmed)
	}
	return string(output), nil
}

func analyzeTrafficOutput(output string) []SystemFinding {
	var findings []SystemFinding
	suspiciousPorts := []string{":1337", ":4444", ":5555", ":6666", ":9001", ":31337"}
	suspiciousProcesses := []string{"php", "python", "perl", "ruby", "node", "bash", "sh", "zsh", "nc", "ncat", "socat", "curl", "wget"}

	for _, rawLine := range strings.Split(output, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}
		lower := strings.ToLower(line)

		for _, port := range suspiciousPorts {
			if strings.Contains(lower, port) {
				findings = append(findings, newFinding(
					"traffic",
					"high",
					"Suspicious listening port",
					line,
				))
				goto nextLine
			}
		}

		for _, proc := range suspiciousProcesses {
			if strings.Contains(lower, proc) && (strings.Contains(lower, "listen") || strings.Contains(lower, "(listen)") || strings.Contains(lower, "*:")) {
				findings = append(findings, newFinding(
					"traffic",
					"medium",
					"Interpreter or shell process is listening on a port",
					line,
				))
				goto nextLine
			}
		}

	nextLine:
	}

	return findings
}

func runTrafficScan() ([]SystemFinding, []string) {
	var warnings []string
	var findings []SystemFinding

	if !currentUserIsRoot() {
		warnings = appendUnique(warnings, permissionWarningFor("traffic inspection may be partial"))
	}

	switch {
	case commandAvailable("lsof"):
		output, err := runCommandOutput("lsof", "-nP", "-iTCP", "-sTCP:LISTEN")
		if err != nil {
			if isPermissionIssue(err) {
				warnings = appendUnique(warnings, permissionWarningFor("lsof"))
				return findings, warnings
			}
			warnings = appendUnique(warnings, fmt.Sprintf("traffic scan warning: %v", err))
			return findings, warnings
		}
		findings = append(findings, analyzeTrafficOutput(output)...)
	case commandAvailable("netstat"):
		output, err := runCommandOutput("netstat", "-an")
		if err != nil {
			if isPermissionIssue(err) {
				warnings = appendUnique(warnings, permissionWarningFor("netstat"))
				return findings, warnings
			}
			warnings = appendUnique(warnings, fmt.Sprintf("traffic scan warning: %v", err))
			return findings, warnings
		}
		findings = append(findings, analyzeTrafficOutput(output)...)
	default:
		warnings = appendUnique(warnings, "traffic scan skipped because no supported system command is available")
	}

	return findings, warnings
}

func parseSuspiciousLogLine(source, line string) []SystemFinding {
	lower := strings.ToLower(strings.TrimSpace(line))
	if lower == "" {
		return nil
	}

	type signature struct {
		category string
		severity string
		title    string
		patterns []string
	}

	signatures := []signature{
		{
			category: "log",
			severity: "high",
			title:    "Potential webshell or RCE probing in web logs",
			patterns: []string{"cmd=", "exec=", "shell=", "base64_", "base64%5f", "system(", "passthru(", "phpunit", ".env", "/vendor/", "auto_prepend_file", "allow_url_include"},
		},
		{
			category: "log",
			severity: "high",
			title:    "Potential upload or dropper activity in logs",
			patterns: []string{"multipart/form-data", "filename=", ".php", ".phtml", "move_uploaded_file", "/upload", "/uploader"},
		},
		{
			category: "log",
			severity: "medium",
			title:    "Authentication attack pattern detected",
			patterns: []string{"failed password", "invalid user", "authentication failure", "maximum authentication attempts", "did not receive identification string"},
		},
		{
			category: "log",
			severity: "high",
			title:    "Potential privilege escalation or command abuse in auth logs",
			patterns: []string{"sudo:", "session opened for user root", "useradd", "usermod", "chattr", "curl ", "wget ", "nc ", "bash -c", "chmod 777", "chmod +s"},
		},
	}

	var findings []SystemFinding
	for _, sig := range signatures {
		for _, pattern := range sig.patterns {
			if strings.Contains(lower, pattern) {
				findings = append(findings, newFinding(
					sig.category,
					sig.severity,
					sig.title,
					fmt.Sprintf("%s: %s", source, shortenEvidence(line)),
				))
				break
			}
		}
	}

	return findings
}

func scanLogFile(path string, findings []SystemFinding, warnings []string) ([]SystemFinding, []string) {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return findings, warnings
		}
		if isPermissionIssue(err) {
			warnings = appendUnique(warnings, permissionWarningFor(path))
			return findings, warnings
		}
		warnings = appendUnique(warnings, fmt.Sprintf("log scan warning: %v", err))
		return findings, warnings
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	buf := make([]byte, 1024*1024)
	scanner.Buffer(buf, 20*1024*1024)
	var tail []string
	for scanner.Scan() {
		tail = append(tail, scanner.Text())
		if len(tail) > 400 {
			tail = tail[1:]
		}
	}
	if err := scanner.Err(); err != nil {
		if isPermissionIssue(err) {
			warnings = appendUnique(warnings, permissionWarningFor(path))
			return findings, warnings
		}
		warnings = appendUnique(warnings, fmt.Sprintf("log scan warning: %v", err))
		return findings, warnings
	}

	for _, line := range tail {
		findings = append(findings, parseSuspiciousLogLine(path, line)...)
	}

	return findings, warnings
}

func runLogScan() ([]SystemFinding, []string) {
	var findings []SystemFinding
	var warnings []string

	commonLogs := []string{
		"/var/log/auth.log",
		"/var/log/secure",
		"/var/log/system.log",
		"/var/log/nginx/access.log",
		"/var/log/nginx/error.log",
		"/var/log/apache2/access.log",
		"/var/log/apache2/error.log",
		"/var/log/httpd/access_log",
		"/var/log/httpd/error_log",
	}

	for _, logPath := range commonLogs {
		findings, warnings = scanLogFile(logPath, findings, warnings)
	}

	if !currentUserIsRoot() {
		warnings = appendUnique(warnings, permissionWarningFor("log inspection may be partial"))
	}

	return findings, warnings
}

func analyzeRKHunterOutput(output string) []SystemFinding {
	var findings []SystemFinding
	for _, rawLine := range strings.Split(output, "\n") {
		line := strings.TrimSpace(rawLine)
		lower := strings.ToLower(line)
		if line == "" {
			continue
		}
		if strings.Contains(lower, "warning") || strings.Contains(lower, "infected") || strings.Contains(lower, "suspect") || strings.Contains(lower, "rootkit") {
			findings = append(findings, newFinding(
				"rootkit",
				"high",
				"rkhunter reported a suspicious result",
				line,
			))
		}
	}
	return findings
}

func analyzeChkrootkitOutput(output string) []SystemFinding {
	var findings []SystemFinding
	for _, rawLine := range strings.Split(output, "\n") {
		line := strings.TrimSpace(rawLine)
		lower := strings.ToLower(line)
		if line == "" {
			continue
		}
		if strings.Contains(lower, "infected") || strings.Contains(lower, "suspicious") || strings.Contains(lower, "possible") || strings.Contains(lower, "warning") {
			if strings.Contains(lower, "not infected") || strings.Contains(lower, "nothing found") {
				continue
			}
			findings = append(findings, newFinding(
				"rootkit",
				"high",
				"chkrootkit reported a suspicious result",
				line,
			))
		}
	}
	return findings
}

func analyzeUnhideOutput(output string) []SystemFinding {
	var findings []SystemFinding
	for _, rawLine := range strings.Split(output, "\n") {
		line := strings.TrimSpace(rawLine)
		lower := strings.ToLower(line)
		if line == "" {
			continue
		}
		if strings.Contains(lower, "hidden") || strings.Contains(lower, "suspicious") || strings.Contains(lower, "invisible") {
			findings = append(findings, newFinding(
				"rootkit",
				"medium",
				"unhide reported hidden or suspicious activity",
				line,
			))
		}
	}
	return findings
}

func inspectExecutablePath(path string, findings []SystemFinding, warnings []string, title string) ([]SystemFinding, []string) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return findings, warnings
		}
		if isPermissionIssue(err) {
			warnings = appendUnique(warnings, permissionWarningFor(path))
			return findings, warnings
		}
		warnings = appendUnique(warnings, fmt.Sprintf("rootkit scan warning: %v", err))
		return findings, warnings
	}

	if info.Mode().IsRegular() && info.Mode().Perm()&0111 != 0 {
		findings = append(findings, newFinding(
			"rootkit",
			"medium",
			title,
			path,
		))
	}
	return findings, warnings
}

func inspectPathForRootkitIndicators(path string, findings []SystemFinding, warnings []string) ([]SystemFinding, []string) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return findings, warnings
		}
		if isPermissionIssue(err) {
			warnings = appendUnique(warnings, permissionWarningFor(path))
			return findings, warnings
		}
		warnings = appendUnique(warnings, fmt.Sprintf("rootkit scan warning: %v", err))
		return findings, warnings
	}

	if info.Size() > 0 {
		findings = append(findings, newFinding(
			"rootkit",
			"high",
			"Sensitive preload file is present",
			fmt.Sprintf("%s exists and is not empty", path),
		))
	}
	return findings, warnings
}

func scanDirectoryForSuspiciousEntries(dir string, suspiciousNames []string, findings []SystemFinding, warnings []string, title string) ([]SystemFinding, []string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return findings, warnings
		}
		if isPermissionIssue(err) {
			warnings = appendUnique(warnings, permissionWarningFor(dir))
			return findings, warnings
		}
		warnings = appendUnique(warnings, fmt.Sprintf("rootkit scan warning: %v", err))
		return findings, warnings
	}

	for _, entry := range entries {
		lowerName := strings.ToLower(entry.Name())
		for _, suspiciousName := range suspiciousNames {
			if !strings.Contains(lowerName, suspiciousName) {
				continue
			}
			findings = append(findings, newFinding(
				"rootkit",
				"high",
				title,
				filepath.Join(dir, entry.Name()),
			))
			break
		}
	}

	return findings, warnings
}

func scanHiddenExecutables(dir string, findings []SystemFinding, warnings []string) ([]SystemFinding, []string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return findings, warnings
		}
		if isPermissionIssue(err) {
			warnings = appendUnique(warnings, permissionWarningFor(dir))
			return findings, warnings
		}
		warnings = appendUnique(warnings, fmt.Sprintf("rootkit scan warning: %v", err))
		return findings, warnings
	}

	for _, entry := range entries {
		name := entry.Name()
		lower := strings.ToLower(name)
		if !strings.HasPrefix(name, ".") && !containsAny(lower, "diamorphine", "reptile", "phalanx", "suterusu", "kinsing", "xorddos") {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		if info.Mode().IsRegular() && info.Mode().Perm()&0111 != 0 {
			findings = append(findings, newFinding(
				"rootkit",
				"medium",
				"Hidden executable found in a temporary directory",
				filepath.Join(dir, name),
			))
		}
	}

	return findings, warnings
}

func scanSuspiciousPrivilegeEscalationFiles(dir string, findings []SystemFinding, warnings []string) ([]SystemFinding, []string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return findings, warnings
		}
		if isPermissionIssue(err) {
			warnings = appendUnique(warnings, permissionWarningFor(dir))
			return findings, warnings
		}
		warnings = appendUnique(warnings, fmt.Sprintf("rootkit scan warning: %v", err))
		return findings, warnings
	}

	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}

		mode := info.Mode()
		if !mode.IsRegular() {
			continue
		}

		if hasPrivilegeEscalationBits(mode) {
			findings = append(findings, newFinding(
				"rootkit",
				"high",
				"Suspicious privileged executable found in temporary directory",
				filepath.Join(dir, entry.Name()),
			))
		}
	}

	return findings, warnings
}

func hasPrivilegeEscalationBits(mode os.FileMode) bool {
	return mode&os.ModeSetuid != 0 || mode&os.ModeSetgid != 0
}

func scanLinuxPersistencePoints(findings []SystemFinding, warnings []string) ([]SystemFinding, []string) {
	suspiciousNames := []string{"reptile", "diamorphine", "phalanx", "suterusu", "adore", "xorddos", "kinsing"}

	findings, warnings = inspectExecutablePath("/etc/rc.local", findings, warnings, "Executable rc.local detected")
	findings, warnings = scanDirectoryForSuspiciousEntries("/etc/cron.d", suspiciousNames, findings, warnings, "Suspicious cron artifact name detected")
	findings, warnings = scanDirectoryForSuspiciousEntries("/etc/systemd/system", suspiciousNames, findings, warnings, "Suspicious systemd unit name detected")
	findings, warnings = scanDirectoryForSuspiciousEntries("/usr/lib/systemd/system", suspiciousNames, findings, warnings, "Suspicious packaged systemd unit name detected")
	findings, warnings = scanDirectoryForSuspiciousEntries("/lib/modules", suspiciousNames, findings, warnings, "Suspicious kernel module directory name detected")

	return findings, warnings
}

func scanMacPersistencePoints(findings []SystemFinding, warnings []string) ([]SystemFinding, []string) {
	suspiciousNames := []string{"reptile", "diamorphine", "phalanx", "suterusu", "adore", "xorddos", "kinsing"}

	findings, warnings = scanDirectoryForSuspiciousEntries("/Library/LaunchDaemons", suspiciousNames, findings, warnings, "Suspicious LaunchDaemon name detected")
	findings, warnings = scanDirectoryForSuspiciousEntries("/Library/LaunchAgents", suspiciousNames, findings, warnings, "Suspicious LaunchAgent name detected")

	return findings, warnings
}

func scanProcModules(findings []SystemFinding, warnings []string) ([]SystemFinding, []string) {
	if runtime.GOOS != "linux" {
		return findings, warnings
	}

	content, err := os.ReadFile("/proc/modules")
	if err != nil {
		if isPermissionIssue(err) {
			warnings = appendUnique(warnings, permissionWarningFor("/proc/modules"))
			return findings, warnings
		}
		return findings, warnings
	}

	knownModules := []string{"diamorphine", "reptile", "phalanx", "adore", "suterusu"}
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		lower := strings.ToLower(line)
		for _, module := range knownModules {
			if strings.Contains(lower, module) {
				findings = append(findings, newFinding(
					"rootkit",
					"high",
					"Known suspicious kernel module name found",
					line,
				))
				break
			}
		}
	}

	return findings, warnings
}

func runRootkitScan() ([]SystemFinding, []string) {
	var findings []SystemFinding
	var warnings []string

	if !currentUserIsRoot() {
		warnings = appendUnique(warnings, permissionWarningFor("rootkit inspection may be partial"))
	}

	externalToolRan := false

	if runtime.GOOS == "linux" && commandAvailable("rkhunter") {
		externalToolRan = true
		output, err := runCommandOutput("rkhunter", "--check", "--sk", "--nocolors")
		if err != nil {
			if isPermissionIssue(err) {
				warnings = appendUnique(warnings, permissionWarningFor("rkhunter"))
			} else {
				warnings = appendUnique(warnings, fmt.Sprintf("rkhunter warning: %v", err))
			}
		}
		findings = append(findings, analyzeRKHunterOutput(output)...)
	}

	if runtime.GOOS == "linux" && commandAvailable("chkrootkit") {
		externalToolRan = true
		output, err := runCommandOutput("chkrootkit")
		if err != nil {
			if isPermissionIssue(err) {
				warnings = appendUnique(warnings, permissionWarningFor("chkrootkit"))
			} else {
				warnings = appendUnique(warnings, fmt.Sprintf("chkrootkit warning: %v", err))
			}
		}
		findings = append(findings, analyzeChkrootkitOutput(output)...)
	}

	if runtime.GOOS == "linux" && commandAvailable("unhide") {
		externalToolRan = true
		output, err := runCommandOutput("unhide", "quick")
		if err != nil {
			if isPermissionIssue(err) {
				warnings = appendUnique(warnings, permissionWarningFor("unhide"))
			} else {
				warnings = appendUnique(warnings, fmt.Sprintf("unhide warning: %v", err))
			}
		}
		findings = append(findings, analyzeUnhideOutput(output)...)
	}

	if !externalToolRan {
		warnings = appendUnique(warnings, "no external rootkit tool found; using built-in heuristics only")
	}

	if runtime.GOOS == "linux" {
		findings, warnings = inspectPathForRootkitIndicators("/etc/ld.so.preload", findings, warnings)
		findings, warnings = scanHiddenExecutables("/tmp", findings, warnings)
		findings, warnings = scanHiddenExecutables("/var/tmp", findings, warnings)
		findings, warnings = scanHiddenExecutables("/dev/shm", findings, warnings)
		findings, warnings = scanSuspiciousPrivilegeEscalationFiles("/tmp", findings, warnings)
		findings, warnings = scanSuspiciousPrivilegeEscalationFiles("/var/tmp", findings, warnings)
		findings, warnings = scanSuspiciousPrivilegeEscalationFiles("/dev/shm", findings, warnings)
		findings, warnings = scanProcModules(findings, warnings)
		findings, warnings = scanLinuxPersistencePoints(findings, warnings)
		return findings, warnings
	}

	if runtime.GOOS == "darwin" {
		findings, warnings = scanHiddenExecutables("/tmp", findings, warnings)
		findings, warnings = scanSuspiciousPrivilegeEscalationFiles("/tmp", findings, warnings)
		findings, warnings = scanMacPersistencePoints(findings, warnings)
		warnings = appendUnique(warnings, "macOS rootkit heuristics are limited; run with elevated privileges for fuller visibility")
	}

	return findings, warnings
}

func printSystemFindings(title string, findings []SystemFinding) {
	fmt.Printf("\n%s%s:%s\n", Yellow, title, Reset)
	if len(findings) == 0 {
		fmt.Printf("%sNo findings in this section.%s\n", Green, Reset)
		return
	}
	for _, finding := range findings {
		fmt.Printf("- [%s] %s\n", strings.ToUpper(finding.Severity), finding.Title)
		fmt.Printf("  %s\n", finding.Detail)
	}
}

func printWarnings(warnings []string) {
	if len(warnings) == 0 {
		return
	}
	fmt.Printf("\n%sWarnings:%s\n", Magenta, Reset)
	for _, warning := range warnings {
		fmt.Printf("- %s\n", warning)
	}
}

func writeDeepScanToFile(path string, summary *DeepScanSummary) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	fmt.Fprintln(writer, "WorldShellFinder Deep Scan Report")
	fmt.Fprintf(writer, "Generated: %s\n\n", time.Now().Format("2006-01-02 15:04:05"))

	if summary.FileSummary != nil {
		fmt.Fprintln(writer, "[File Detections]")
		fmt.Fprintf(writer, "Total files scanned: %d\n", summary.FileSummary.totalFilesScanned)
		fmt.Fprintf(writer, "Potential webshells found: %d\n", len(summary.FileSummary.detections))
		for _, detect := range summary.FileSummary.detections {
			fmt.Fprintf(writer, "- %s (score: %d)\n", detect.path, detect.score)
		}
		fmt.Fprintln(writer)
	}

	fmt.Fprintln(writer, "[Suspicious Traffic]")
	for _, finding := range summary.TrafficFindings {
		fmt.Fprintf(writer, "- [%s] %s: %s\n", strings.ToUpper(finding.Severity), finding.Title, finding.Detail)
	}
	if len(summary.TrafficFindings) == 0 {
		fmt.Fprintln(writer, "- No suspicious traffic findings")
	}
	fmt.Fprintln(writer)

	fmt.Fprintln(writer, "[Suspicious Logs]")
	for _, finding := range summary.LogFindings {
		fmt.Fprintf(writer, "- [%s] %s: %s\n", strings.ToUpper(finding.Severity), finding.Title, finding.Detail)
	}
	if len(summary.LogFindings) == 0 {
		fmt.Fprintln(writer, "- No suspicious log findings")
	}
	fmt.Fprintln(writer)

	fmt.Fprintln(writer, "[Rootkit Findings]")
	for _, finding := range summary.RootkitFindings {
		fmt.Fprintf(writer, "- [%s] %s: %s\n", strings.ToUpper(finding.Severity), finding.Title, finding.Detail)
	}
	if len(summary.RootkitFindings) == 0 {
		fmt.Fprintln(writer, "- No suspicious rootkit findings")
	}
	fmt.Fprintln(writer)

	fmt.Fprintln(writer, "[Warnings]")
	for _, warning := range summary.Warnings {
		fmt.Fprintf(writer, "- %s\n", warning)
	}
	if len(summary.Warnings) == 0 {
		fmt.Fprintln(writer, "- No warnings")
	}

	return writer.Flush()
}

func runDeepScan(directory, wordlistPath, outputFile string, minScore, maxEvidence int) error {
	cfg, err := buildScanConfig(wordlistPath, minScore, maxEvidence)
	if err != nil {
		return err
	}

	done := make(chan bool)
	go loadingAnimation(done)
	fileSummary, err := scanDirectory(directory, cfg)
	if err != nil {
		done <- true
		return err
	}
	trafficFindings, trafficWarnings := runTrafficScan()
	logFindings, logWarnings := runLogScan()
	rootkitFindings, rootkitWarnings := runRootkitScan()
	done <- true

	warnings := append([]string{}, trafficWarnings...)
	for _, warning := range logWarnings {
		warnings = appendUnique(warnings, warning)
	}
	for _, warning := range rootkitWarnings {
		warnings = appendUnique(warnings, warning)
	}

	summary := &DeepScanSummary{
		FileSummary:     fileSummary,
		TrafficFindings: trafficFindings,
		LogFindings:     logFindings,
		RootkitFindings: rootkitFindings,
		Warnings:        warnings,
	}

	fmt.Printf("\n%sDeep Scan Summary:%s\n", Cyan, Reset)
	printDetectionSummary(fileSummary)
	printSystemFindings("Suspicious Traffic", trafficFindings)
	printSystemFindings("Suspicious Logs", logFindings)
	printSystemFindings("Rootkit Findings", rootkitFindings)
	printWarnings(warnings)

	if outputFile != "" {
		if err := writeDeepScanToFile(outputFile, summary); err != nil {
			return fmt.Errorf("error writing deep scan output: %w", err)
		}
		fmt.Printf("\nResults have been saved to: %s\n", outputFile)
	}

	return nil
}

func runDetection(directory, wordlistPath, outputFile string, minScore, maxEvidence int) error {
	cfg, err := buildScanConfig(wordlistPath, minScore, maxEvidence)
	if err != nil {
		return err
	}

	done := make(chan bool)
	go loadingAnimation(done)
	summary, err := scanDirectory(directory, cfg)
	done <- true
	if err != nil {
		return err
	}

	printDetectionSummary(summary)
	if outputFile != "" {
		if err := writeDetectionsToFile(outputFile, summary); err != nil {
			return fmt.Errorf("error writing to output file: %w", err)
		}
		fmt.Printf("\nResults have been saved to: %s\n", outputFile)
	}
	return nil
}

func runRemoval(directory, outputFile string, reader *bufio.Reader, removeValue string) error {
	stringToRemove := strings.TrimSpace(removeValue)
	if stringToRemove == "" {
		fmt.Print("Enter string to remove (press Ctrl+D or Ctrl+Z when done): ")

		largeBuffer := make([]byte, 10*1024*1024)
		var totalSize int64
		maxSize := int64(10 * 1024 * 1024)
		var builder strings.Builder
		builder.Grow(len(largeBuffer))

		for {
			n, err := reader.Read(largeBuffer)
			if err == io.EOF {
				break
			}
			if err != nil {
				return fmt.Errorf("error reading input: %w", err)
			}
			totalSize += int64(n)
			if totalSize > maxSize {
				return fmt.Errorf("input exceeds maximum size of 10MB")
			}
			builder.Write(largeBuffer[:n])
		}

		stringToRemove = strings.TrimSpace(builder.String())
	}

	if stringToRemove == "" {
		return fmt.Errorf("empty string provided")
	}

	fmt.Printf("String size to remove: %.2f MB\n", float64(len(stringToRemove))/(1024*1024))

	var modifications []*FileModification
	totalFilesScanned := 0
	totalStringsRemoved := 0

	done := make(chan bool)
	go loadingAnimation(done)

	err := filepath.Walk(directory, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			logWalkIssue(path, walkErr)
			return nil
		}
		if info.IsDir() {
			return nil
		}

		totalFilesScanned++
		modification, err := removeStringFromFile(path, stringToRemove)
		if err != nil {
			logReadIssue(path, err)
			return nil
		}
		if modification != nil {
			modifications = append(modifications, modification)
			totalStringsRemoved += modification.stringsRemoved
		}
		if verbose {
			fmt.Printf("Processed file: %s\n", path)
		}
		return nil
	})

	done <- true
	if err != nil {
		return err
	}

	fmt.Printf("\n%sString Removal Summary:%s\n", Yellow, Reset)
	fmt.Printf("Total files scanned: %d\n", totalFilesScanned)
	fmt.Printf("Total files modified: %d\n", len(modifications))
	fmt.Printf("Total strings removed: %d\n", totalStringsRemoved)

	if outputFile != "" {
		if err := writeModificationsToFile(outputFile, modifications, totalFilesScanned, totalStringsRemoved); err != nil {
			return fmt.Errorf("error writing to output file: %w", err)
		}
		fmt.Printf("\nResults have been saved to: %s\n", outputFile)
	}

	return nil
}

func prompt(reader *bufio.Reader, message string) (string, error) {
	fmt.Print(message)
	value, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}
	return strings.TrimSpace(value), nil
}

func main() {
	helpFlag := flag.Bool("h", false, "display help information")
	helpFlagLong := flag.Bool("help", false, "display help information")
	updateFlag := flag.Bool("update", false, "update latest version from repository")
	verboseFlag := flag.Bool("v", false, "enable verbose mode")
	modeFlag := flag.String("mode", "", "operation mode: detect, deep, or remove")
	dirFlag := flag.String("dir", "", "directory to scan")
	outFlag := flag.String("out", "", "output file path")
	wordlistFlag := flag.String("wordlist", "", "custom wordlist path")
	minScoreFlag := flag.Int("min-score", defaultMinScore, "minimum score before reporting a file")
	maxEvidenceFlag := flag.Int("max-evidence", defaultMaxEvidence, "maximum evidence entries shown per file")
	removeStringFlag := flag.String("remove-string", "", "string to remove in remove mode")
	flag.Parse()

	verbose = *verboseFlag
	fmt.Print(banner)

	if *helpFlag || *helpFlagLong {
		printHelp()
		return
	}

	if *updateFlag {
		if err := updateFromRepository("github.com/Aryma-f4/worldshellfinder"); err != nil {
			log.Fatalf("Error While Updating: %v\n", err)
		}
		fmt.Println("Update done.")
		return
	}

	if *minScoreFlag < 1 {
		log.Fatalf("min-score must be at least 1")
	}
	if *maxEvidenceFlag < 1 {
		log.Fatalf("max-evidence must be at least 1")
	}

	reader := bufio.NewReader(os.Stdin)
	mode := strings.TrimSpace(strings.ToLower(*modeFlag))
	directory := strings.TrimSpace(*dirFlag)
	outputFile := strings.TrimSpace(*outFlag)

	if mode != "" {
		if directory == "" {
			log.Fatalf("dir is required when mode is provided")
		}
		switch mode {
		case "detect":
			if err := runDetection(directory, strings.TrimSpace(*wordlistFlag), outputFile, *minScoreFlag, *maxEvidenceFlag); err != nil {
				log.Fatalf("Detection failed: %v\n", err)
			}
		case "deep":
			if err := runDeepScan(directory, strings.TrimSpace(*wordlistFlag), outputFile, *minScoreFlag, *maxEvidenceFlag); err != nil {
				log.Fatalf("Deep scan failed: %v\n", err)
			}
		case "remove":
			if err := runRemoval(directory, outputFile, reader, *removeStringFlag); err != nil {
				log.Fatalf("String removal failed: %v\n", err)
			}
		default:
			log.Fatalf("invalid mode %q, use detect, deep, or remove", mode)
		}
		return
	}

	fmt.Print(menuText)
	choice, err := prompt(reader, "Enter your choice (1, 2, or 3): ")
	if err != nil {
		log.Fatalf("Failed reading menu choice: %v\n", err)
	}
	if directory == "" {
		directory, err = prompt(reader, "Enter the directory to scan: ")
		if err != nil {
			log.Fatalf("Failed reading directory: %v\n", err)
		}
	}
	if outputFile == "" {
		outputFile, err = prompt(reader, "Enter the output file path (press Enter for no file output): ")
		if err != nil {
			log.Fatalf("Failed reading output file path: %v\n", err)
		}
	}

	switch choice {
	case "1":
		wordlistPath := strings.TrimSpace(*wordlistFlag)
		if wordlistPath == "" {
			wordlistPath, err = prompt(reader, "Enter custom wordlist path (press Enter to skip): ")
			if err != nil {
				log.Fatalf("Failed reading wordlist path: %v\n", err)
			}
		}
		err = runDetection(directory, wordlistPath, outputFile, *minScoreFlag, *maxEvidenceFlag)
		if err != nil {
			log.Fatalf("Detection failed: %v\n", err)
		}
	case "2":
		err = runRemoval(directory, outputFile, reader, *removeStringFlag)
		if err != nil {
			log.Fatalf("String removal failed: %v\n", err)
		}
	case "3":
		wordlistPath := strings.TrimSpace(*wordlistFlag)
		if wordlistPath == "" {
			wordlistPath, err = prompt(reader, "Enter custom wordlist path (press Enter to skip): ")
			if err != nil {
				log.Fatalf("Failed reading wordlist path: %v\n", err)
			}
		}
		err = runDeepScan(directory, wordlistPath, outputFile, *minScoreFlag, *maxEvidenceFlag)
		if err != nil {
			log.Fatalf("Deep scan failed: %v\n", err)
		}
	default:
		fmt.Println("Invalid choice!")
	}
}
