package scanner

import (
	"fmt"
	"strings"

	"github.com/Aryma-f4/worldshellfinder/internal/models"
	"github.com/Aryma-f4/worldshellfinder/internal/utils"
)

func analyzeTrafficOutput(output string) []models.SystemFinding {
	var findings []models.SystemFinding
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
				findings = append(findings, models.SystemFinding{
					Category: "traffic",
					Severity: "high",
					Title:    "Suspicious listening port",
					Detail:   line,
				})
				goto nextLine
			}
		}

		for _, proc := range suspiciousProcesses {
			if strings.Contains(lower, proc) && (strings.Contains(lower, "listen") || strings.Contains(lower, "(listen)") || strings.Contains(lower, "*:")) {
				findings = append(findings, models.SystemFinding{
					Category: "traffic",
					Severity: "medium",
					Title:    "Interpreter or shell process is listening on a port",
					Detail:   line,
				})
				goto nextLine
			}
		}

	nextLine:
	}

	return findings
}

func RunTrafficScan() ([]models.SystemFinding, []string) {
	var warnings []string
	var findings []models.SystemFinding

	if !utils.CurrentUserIsRoot() {
		warnings = utils.AppendUnique(warnings, utils.PermissionWarningFor("traffic inspection may be partial"))
	}

	switch {
	case utils.CommandAvailable("lsof"):
		output, err := utils.RunCommandOutput("lsof", "-nP", "-iTCP", "-sTCP:LISTEN")
		if err != nil {
			if utils.IsPermissionIssue(err) {
				warnings = utils.AppendUnique(warnings, utils.PermissionWarningFor("lsof"))
				return findings, warnings
			}
			warnings = utils.AppendUnique(warnings, fmt.Sprintf("traffic scan warning: %v", err))
			return findings, warnings
		}
		findings = append(findings, analyzeTrafficOutput(output)...)
	case utils.CommandAvailable("netstat"):
		output, err := utils.RunCommandOutput("netstat", "-an")
		if err != nil {
			if utils.IsPermissionIssue(err) {
				warnings = utils.AppendUnique(warnings, utils.PermissionWarningFor("netstat"))
				return findings, warnings
			}
			warnings = utils.AppendUnique(warnings, fmt.Sprintf("traffic scan warning: %v", err))
			return findings, warnings
		}
		findings = append(findings, analyzeTrafficOutput(output)...)
	default:
		warnings = utils.AppendUnique(warnings, "traffic scan skipped because no supported system command is available")
	}

	return findings, warnings
}
