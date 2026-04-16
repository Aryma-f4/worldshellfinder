package main

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

func testScanConfig(t *testing.T) ScanConfig {
	t.Helper()

	rules, err := buildDetectionRules()
	if err != nil {
		t.Fatalf("buildDetectionRules() error = %v", err)
	}

	return ScanConfig{
		Keywords: []string{
			"eval(base64_decode(",
			"$_request['cmd']",
			"$_get['cmd']",
		},
		Rules:       rules,
		MinScore:    defaultMinScore,
		MaxEvidence: defaultMaxEvidence,
	}
}

func TestAnalyzeReaderDetectsKnownShellSignature(t *testing.T) {
	cfg := testScanConfig(t)
	content := `<?php
	echo "ok";
	eval(base64_decode($_POST['payload']));
	`

	detection, err := analyzeReader("sample.php", strings.NewReader(content), cfg)
	if err != nil {
		t.Fatalf("analyzeReader() error = %v", err)
	}
	if detection == nil {
		t.Fatal("expected detection, got nil")
	}
	if detection.score < cfg.MinScore {
		t.Fatalf("expected score >= %d, got %d", cfg.MinScore, detection.score)
	}
}

func TestAnalyzeReaderUsesHeuristicsForCommandExecution(t *testing.T) {
	cfg := testScanConfig(t)
	content := `<?php
	$cmd = $_REQUEST['cmd'];
	system($cmd);
	`

	detection, err := analyzeReader("cmd.php", strings.NewReader(content), cfg)
	if err != nil {
		t.Fatalf("analyzeReader() error = %v", err)
	}
	if detection == nil {
		t.Fatal("expected heuristic detection, got nil")
	}

	foundHeuristic := false
	for _, evidence := range detection.evidences {
		if evidence.Kind == "heuristic" {
			foundHeuristic = true
			break
		}
	}
	if !foundHeuristic {
		t.Fatal("expected at least one heuristic evidence")
	}
}

func TestAnalyzeReaderIgnoresBenignFile(t *testing.T) {
	cfg := testScanConfig(t)
	content := `<?php
	function showProfile(string $name): string {
		return "Hello " . htmlspecialchars($name, ENT_QUOTES, "UTF-8");
	}
	`

	detection, err := analyzeReader("benign.php", strings.NewReader(content), cfg)
	if err != nil {
		t.Fatalf("analyzeReader() error = %v", err)
	}
	if detection != nil {
		t.Fatalf("expected nil detection, got %+v", detection)
	}
}

func TestAnalyzeTrafficOutputDetectsSuspiciousPort(t *testing.T) {
	output := `COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
php      123 root    6u  IPv4  12345      0t0  TCP *:4444 (LISTEN)
`

	findings := analyzeTrafficOutput(output)
	if len(findings) == 0 {
		t.Fatal("expected suspicious traffic finding, got none")
	}
	if findings[0].Category != "traffic" {
		t.Fatalf("expected traffic category, got %q", findings[0].Category)
	}
}

func TestParseSuspiciousLogLineDetectsWebshellProbe(t *testing.T) {
	line := `10.0.0.1 - - [16/Apr/2026:10:10:10 +0000] "GET /shell.php?cmd=id HTTP/1.1" 200 123`
	findings := parseSuspiciousLogLine("/var/log/nginx/access.log", line)
	if len(findings) == 0 {
		t.Fatal("expected suspicious log finding, got none")
	}
	if findings[0].Category != "log" {
		t.Fatalf("expected log category, got %q", findings[0].Category)
	}
}

func TestParseSuspiciousLogLineDetectsAuthAbuse(t *testing.T) {
	line := `Failed password for invalid user admin from 10.0.0.2 port 55222 ssh2`
	findings := parseSuspiciousLogLine("/var/log/auth.log", line)
	if len(findings) == 0 {
		t.Fatal("expected auth abuse finding, got none")
	}
}

func TestAnalyzeRKHunterOutputFindsWarnings(t *testing.T) {
	output := `
[12:10:11] Warning: The command '/bin/evil' has been replaced by a script
[12:10:12] Rootkit suspicious file detected
`

	findings := analyzeRKHunterOutput(output)
	if len(findings) < 2 {
		t.Fatalf("expected multiple rootkit findings, got %d", len(findings))
	}
}

func TestAnalyzeChkrootkitOutputFindsWarnings(t *testing.T) {
	output := `
Searching for suspicious files and dirs... INFECTED
Checking 'bindshell'... possible suspicious match
`

	findings := analyzeChkrootkitOutput(output)
	if len(findings) < 2 {
		t.Fatalf("expected multiple chkrootkit findings, got %d", len(findings))
	}
}

func TestAnalyzeUnhideOutputFindsWarnings(t *testing.T) {
	output := `
Found HIDDEN PID: 4242
Suspicious invisible process reported
`

	findings := analyzeUnhideOutput(output)
	if len(findings) < 2 {
		t.Fatalf("expected multiple unhide findings, got %d", len(findings))
	}
}

func TestIsPermissionIssueDetectsPermissionDenied(t *testing.T) {
	err := fmt.Errorf("open /root/secret: permission denied")
	if !isPermissionIssue(err) {
		t.Fatal("expected permission issue to be detected")
	}
}

func TestScanHiddenExecutablesFindsHiddenExecutable(t *testing.T) {
	dir := t.TempDir()
	target := dir + "/.reptile"
	if err := os.WriteFile(target, []byte("#!/bin/sh\necho test\n"), 0755); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	findings, warnings := scanHiddenExecutables(dir, nil, nil)
	if len(warnings) != 0 {
		t.Fatalf("expected no warnings, got %v", warnings)
	}
	if len(findings) == 0 {
		t.Fatal("expected hidden executable finding, got none")
	}
}

func TestHasPrivilegeEscalationBitsDetectsSetuidAndSetgid(t *testing.T) {
	if !hasPrivilegeEscalationBits(os.ModeSetuid | 0755) {
		t.Fatal("expected setuid mode to be detected")
	}
	if !hasPrivilegeEscalationBits(os.ModeSetgid | 0755) {
		t.Fatal("expected setgid mode to be detected")
	}
	if hasPrivilegeEscalationBits(0755) {
		t.Fatal("did not expect normal executable mode to be flagged")
	}
}
