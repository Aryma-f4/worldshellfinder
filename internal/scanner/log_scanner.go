package scanner

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/Aryma-f4/worldshellfinder/internal/models"
	"github.com/Aryma-f4/worldshellfinder/internal/utils"
)

func parseSuspiciousLogLine(source, line string) []models.SystemFinding {
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

	var findings []models.SystemFinding
	for _, sig := range signatures {
		for _, pattern := range sig.patterns {
			if strings.Contains(lower, pattern) {
				findings = append(findings, models.SystemFinding{
					Category: sig.category,
					Severity: sig.severity,
					Title:    sig.title,
					Detail:   fmt.Sprintf("%s: %s", source, utils.ShortenEvidence(line)),
				})
				break
			}
		}
	}

	return findings
}

func scanLogFile(path string, findings []models.SystemFinding, warnings []string) ([]models.SystemFinding, []string) {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return findings, warnings
		}
		if utils.IsPermissionIssue(err) {
			warnings = utils.AppendUnique(warnings, utils.PermissionWarningFor(path))
			return findings, warnings
		}
		warnings = utils.AppendUnique(warnings, fmt.Sprintf("log scan warning: %v", err))
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
		if utils.IsPermissionIssue(err) {
			warnings = utils.AppendUnique(warnings, utils.PermissionWarningFor(path))
			return findings, warnings
		}
		warnings = utils.AppendUnique(warnings, fmt.Sprintf("log scan warning: %v", err))
		return findings, warnings
	}

	for _, line := range tail {
		findings = append(findings, parseSuspiciousLogLine(path, line)...)
	}

	return findings, warnings
}

func RunLogScan() ([]models.SystemFinding, []string) {
	var findings []models.SystemFinding
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

	if !utils.CurrentUserIsRoot() {
		warnings = utils.AppendUnique(warnings, utils.PermissionWarningFor("log inspection may be partial"))
	}

	return findings, warnings
}
