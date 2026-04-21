package utils

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"math"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Aryma-f4/worldshellfinder/internal/config"
	"github.com/pterm/pterm"
)

func LoadingAnimation(done chan bool) {
	chars := []rune{'|', '/', '-', '\\'}
	for {
		select {
		case <-done:
			return
		default:
			for _, c := range chars {
				fmt.Printf("\rProcessing... %c", c)
				time.Sleep(100 * time.Millisecond)
			}
		}
	}
}

func IsPermissionIssue(err error) bool {
	if err == nil {
		return false
	}
	if os.IsPermission(err) {
		return true
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "permission denied") || strings.Contains(message, "operation not permitted")
}

func PermissionWarningFor(path string) string {
	if path == "" {
		return config.RootPermissionWarning
	}
	return fmt.Sprintf("%s (%s)", config.RootPermissionWarning, path)
}

func LogWalkIssue(path string, err error) {
	if IsPermissionIssue(err) {
		pterm.Warning.Printf("%s\n", PermissionWarningFor(path))
		return
	}
	pterm.Error.Printf("Error accessing file or directory %s: %v\n", path, err)
}

func LogReadIssue(path string, err error) {
	if IsPermissionIssue(err) {
		pterm.Warning.Printf("%s\n", PermissionWarningFor(path))
		return
	}
	pterm.Error.Printf("Error reading file %s: %v\n", path, err)
}

func AppendUnique(values []string, value string) []string {
	if slices.Contains(values, value) {
		return values
	}
	return append(values, value)
}

func CurrentUserIsRoot() bool {
	if runtime.GOOS == "windows" {
		return false
	}
	output, err := exec.Command("id", "-u").Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(output)) == "0"
}

func CommandAvailable(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func RunCommandOutput(name string, args ...string) (string, error) {
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

func ContainsAny(line string, patterns ...string) bool {
	for _, pattern := range patterns {
		if strings.Contains(line, pattern) {
			return true
		}
	}
	return false
}

func ShortenEvidence(line string) string {
	clean := strings.TrimSpace(line)
	if len(clean) <= 180 {
		return clean
	}
	return clean[:177] + "..."
}

func LooksLikeText(sample []byte) bool {
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

func CalculateEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	freq := make(map[byte]float64)
	for _, b := range data {
		freq[b]++
	}
	entropy := 0.0
	for _, f := range freq {
		p := f / float64(len(data))
		entropy -= p * math.Log2(p)
	}
	return entropy
}

var base64Rx = regexp.MustCompile(`^[A-Za-z0-9+/]+={0,2}$`)

func LooksLikeBase64Token(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) < 40 || len(s) > 4096 {
		return false
	}
	if len(s)%4 != 0 {
		return false
	}
	return base64Rx.MatchString(s)
}

func TryDecodeBase64Token(s string, maxDecodedBytes int) ([]byte, bool) {
	if !LooksLikeBase64Token(s) {
		return nil, false
	}
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, false
	}
	if maxDecodedBytes > 0 && len(decoded) > maxDecodedBytes {
		decoded = decoded[:maxDecodedBytes]
	}
	return decoded, true
}

func DecodedLooksLikePayload(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	lower := strings.ToLower(string(b))
	return strings.Contains(lower, "<?php") ||
		strings.Contains(lower, "eval(") ||
		strings.Contains(lower, "system(") ||
		strings.Contains(lower, "shell_exec(") ||
		strings.Contains(lower, "passthru(") ||
		strings.Contains(lower, "child_process") ||
		strings.Contains(lower, "runtime.getruntime().exec") ||
		strings.Contains(lower, "processbuilder(") ||
		strings.Contains(lower, "powershell") ||
		strings.Contains(lower, "/bin/bash") ||
		strings.Contains(lower, "/bin/sh")
}
