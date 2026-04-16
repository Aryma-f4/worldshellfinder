package models

import "regexp"

type FileModification struct {
	Path           string
	OriginalSize   int64
	ModifiedSize   int64
	StringsRemoved int
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
	Path      string
	Score     int
	Evidences []ShellEvidence
}

type ScanConfig struct {
	Keywords    []string
	Rules       []DetectionRule
	MinScore    int
	MaxEvidence int
	VTApiKey    string
}

type ScanSummary struct {
	Detections        []*ShellDetection
	TotalFilesScanned int
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
