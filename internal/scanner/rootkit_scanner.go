package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/Aryma-f4/worldshellfinder/internal/models"
	"github.com/Aryma-f4/worldshellfinder/internal/utils"
)

func analyzeRKHunterOutput(output string) []models.SystemFinding {
	var findings []models.SystemFinding
	for _, rawLine := range strings.Split(output, "\n") {
		line := strings.TrimSpace(rawLine)
		lower := strings.ToLower(line)
		if line == "" {
			continue
		}
		if strings.Contains(lower, "warning") || strings.Contains(lower, "infected") || strings.Contains(lower, "suspect") || strings.Contains(lower, "rootkit") {
			findings = append(findings, models.SystemFinding{
				Category: "rootkit",
				Severity: "high",
				Title:    "rkhunter reported a suspicious result",
				Detail:   line,
			})
		}
	}
	return findings
}

func analyzeChkrootkitOutput(output string) []models.SystemFinding {
	var findings []models.SystemFinding
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
			findings = append(findings, models.SystemFinding{
				Category: "rootkit",
				Severity: "high",
				Title:    "chkrootkit reported a suspicious result",
				Detail:   line,
			})
		}
	}
	return findings
}

func analyzeUnhideOutput(output string) []models.SystemFinding {
	var findings []models.SystemFinding
	for _, rawLine := range strings.Split(output, "\n") {
		line := strings.TrimSpace(rawLine)
		lower := strings.ToLower(line)
		if line == "" {
			continue
		}
		if strings.Contains(lower, "hidden") || strings.Contains(lower, "suspicious") || strings.Contains(lower, "invisible") {
			findings = append(findings, models.SystemFinding{
				Category: "rootkit",
				Severity: "medium",
				Title:    "unhide reported hidden or suspicious activity",
				Detail:   line,
			})
		}
	}
	return findings
}

func inspectExecutablePath(path string, findings []models.SystemFinding, warnings []string, title string) ([]models.SystemFinding, []string) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return findings, warnings
		}
		if utils.IsPermissionIssue(err) {
			warnings = utils.AppendUnique(warnings, utils.PermissionWarningFor(path))
			return findings, warnings
		}
		warnings = utils.AppendUnique(warnings, fmt.Sprintf("rootkit scan warning: %v", err))
		return findings, warnings
	}

	if info.Mode().IsRegular() && info.Mode().Perm()&0111 != 0 {
		findings = append(findings, models.SystemFinding{
			Category: "rootkit",
			Severity: "medium",
			Title:    title,
			Detail:   path,
		})
	}
	return findings, warnings
}

func inspectPathForRootkitIndicators(path string, findings []models.SystemFinding, warnings []string) ([]models.SystemFinding, []string) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return findings, warnings
		}
		if utils.IsPermissionIssue(err) {
			warnings = utils.AppendUnique(warnings, utils.PermissionWarningFor(path))
			return findings, warnings
		}
		warnings = utils.AppendUnique(warnings, fmt.Sprintf("rootkit scan warning: %v", err))
		return findings, warnings
	}

	if info.Size() > 0 {
		findings = append(findings, models.SystemFinding{
			Category: "rootkit",
			Severity: "high",
			Title:    "Sensitive preload file is present",
			Detail:   fmt.Sprintf("%s exists and is not empty", path),
		})
	}
	return findings, warnings
}

func scanDirectoryForSuspiciousEntries(dir string, suspiciousNames []string, findings []models.SystemFinding, warnings []string, title string) ([]models.SystemFinding, []string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return findings, warnings
		}
		if utils.IsPermissionIssue(err) {
			warnings = utils.AppendUnique(warnings, utils.PermissionWarningFor(dir))
			return findings, warnings
		}
		warnings = utils.AppendUnique(warnings, fmt.Sprintf("rootkit scan warning: %v", err))
		return findings, warnings
	}

	for _, entry := range entries {
		lowerName := strings.ToLower(entry.Name())
		for _, suspiciousName := range suspiciousNames {
			if !strings.Contains(lowerName, suspiciousName) {
				continue
			}
			findings = append(findings, models.SystemFinding{
				Category: "rootkit",
				Severity: "high",
				Title:    title,
				Detail:   filepath.Join(dir, entry.Name()),
			})
			break
		}
	}

	return findings, warnings
}

func scanHiddenExecutables(dir string, findings []models.SystemFinding, warnings []string) ([]models.SystemFinding, []string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return findings, warnings
		}
		if utils.IsPermissionIssue(err) {
			warnings = utils.AppendUnique(warnings, utils.PermissionWarningFor(dir))
			return findings, warnings
		}
		warnings = utils.AppendUnique(warnings, fmt.Sprintf("rootkit scan warning: %v", err))
		return findings, warnings
	}

	for _, entry := range entries {
		name := entry.Name()
		lower := strings.ToLower(name)
		if !strings.HasPrefix(name, ".") && !utils.ContainsAny(lower, "diamorphine", "reptile", "phalanx", "suterusu", "kinsing", "xorddos") {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		if info.Mode().IsRegular() && info.Mode().Perm()&0111 != 0 {
			findings = append(findings, models.SystemFinding{
				Category: "rootkit",
				Severity: "medium",
				Title:    "Hidden executable found in a temporary directory",
				Detail:   filepath.Join(dir, name),
			})
		}
	}

	return findings, warnings
}

func scanSuspiciousPrivilegeEscalationFiles(dir string, findings []models.SystemFinding, warnings []string) ([]models.SystemFinding, []string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return findings, warnings
		}
		if utils.IsPermissionIssue(err) {
			warnings = utils.AppendUnique(warnings, utils.PermissionWarningFor(dir))
			return findings, warnings
		}
		warnings = utils.AppendUnique(warnings, fmt.Sprintf("rootkit scan warning: %v", err))
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

		if mode&os.ModeSetuid != 0 || mode&os.ModeSetgid != 0 {
			findings = append(findings, models.SystemFinding{
				Category: "rootkit",
				Severity: "high",
				Title:    "Suspicious privileged executable found in temporary directory",
				Detail:   filepath.Join(dir, entry.Name()),
			})
		}
	}

	return findings, warnings
}

func scanLinuxPersistencePoints(findings []models.SystemFinding, warnings []string) ([]models.SystemFinding, []string) {
	suspiciousNames := []string{"reptile", "diamorphine", "phalanx", "suterusu", "adore", "xorddos", "kinsing"}

	findings, warnings = inspectExecutablePath("/etc/rc.local", findings, warnings, "Executable rc.local detected")
	findings, warnings = scanDirectoryForSuspiciousEntries("/etc/cron.d", suspiciousNames, findings, warnings, "Suspicious cron artifact name detected")
	findings, warnings = scanDirectoryForSuspiciousEntries("/etc/systemd/system", suspiciousNames, findings, warnings, "Suspicious systemd unit name detected")
	findings, warnings = scanDirectoryForSuspiciousEntries("/usr/lib/systemd/system", suspiciousNames, findings, warnings, "Suspicious packaged systemd unit name detected")
	findings, warnings = scanDirectoryForSuspiciousEntries("/lib/modules", suspiciousNames, findings, warnings, "Suspicious kernel module directory name detected")

	return findings, warnings
}

func scanMacPersistencePoints(findings []models.SystemFinding, warnings []string) ([]models.SystemFinding, []string) {
	suspiciousNames := []string{"reptile", "diamorphine", "phalanx", "suterusu", "adore", "xorddos", "kinsing"}

	findings, warnings = scanDirectoryForSuspiciousEntries("/Library/LaunchDaemons", suspiciousNames, findings, warnings, "Suspicious LaunchDaemon name detected")
	findings, warnings = scanDirectoryForSuspiciousEntries("/Library/LaunchAgents", suspiciousNames, findings, warnings, "Suspicious LaunchAgent name detected")

	return findings, warnings
}

func scanProcModules(findings []models.SystemFinding, warnings []string) ([]models.SystemFinding, []string) {
	if runtime.GOOS != "linux" {
		return findings, warnings
	}

	content, err := os.ReadFile("/proc/modules")
	if err != nil {
		if utils.IsPermissionIssue(err) {
			warnings = utils.AppendUnique(warnings, utils.PermissionWarningFor("/proc/modules"))
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
				findings = append(findings, models.SystemFinding{
					Category: "rootkit",
					Severity: "high",
					Title:    "Known suspicious kernel module name found",
					Detail:   line,
				})
				break
			}
		}
	}

	return findings, warnings
}

func RunRootkitScan() ([]models.SystemFinding, []string) {
	var findings []models.SystemFinding
	var warnings []string

	if !utils.CurrentUserIsRoot() {
		warnings = utils.AppendUnique(warnings, utils.PermissionWarningFor("rootkit inspection may be partial"))
	}

	externalToolRan := false

	if runtime.GOOS == "linux" && utils.CommandAvailable("rkhunter") {
		externalToolRan = true
		output, err := utils.RunCommandOutput("rkhunter", "--check", "--sk", "--nocolors")
		if err != nil {
			if utils.IsPermissionIssue(err) {
				warnings = utils.AppendUnique(warnings, utils.PermissionWarningFor("rkhunter"))
			} else {
				warnings = utils.AppendUnique(warnings, fmt.Sprintf("rkhunter warning: %v", err))
			}
		}
		findings = append(findings, analyzeRKHunterOutput(output)...)
	}

	if runtime.GOOS == "linux" && utils.CommandAvailable("chkrootkit") {
		externalToolRan = true
		output, err := utils.RunCommandOutput("chkrootkit")
		if err != nil {
			if utils.IsPermissionIssue(err) {
				warnings = utils.AppendUnique(warnings, utils.PermissionWarningFor("chkrootkit"))
			} else {
				warnings = utils.AppendUnique(warnings, fmt.Sprintf("chkrootkit warning: %v", err))
			}
		}
		findings = append(findings, analyzeChkrootkitOutput(output)...)
	}

	if runtime.GOOS == "linux" && utils.CommandAvailable("unhide") {
		externalToolRan = true
		output, err := utils.RunCommandOutput("unhide", "quick")
		if err != nil {
			if utils.IsPermissionIssue(err) {
				warnings = utils.AppendUnique(warnings, utils.PermissionWarningFor("unhide"))
			} else {
				warnings = utils.AppendUnique(warnings, fmt.Sprintf("unhide warning: %v", err))
			}
		}
		findings = append(findings, analyzeUnhideOutput(output)...)
	}

	if !externalToolRan {
		warnings = utils.AppendUnique(warnings, "no external rootkit tool found; using built-in heuristics only")
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
		warnings = utils.AppendUnique(warnings, "macOS rootkit heuristics are limited; run with elevated privileges for fuller visibility")
	}

	return findings, warnings
}
