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
	Path       string
	Score      int
	Confidence string
	Evidences  []ShellEvidence
}

type KeywordRule struct {
	Word   string
	Weight int
}

type ScanConfig struct {
	GeneralKeywords  []KeywordRule
	ExtKeywords      map[string][]KeywordRule
	Rules            []DetectionRule
	MinScore         int
	MaxEvidence      int
	VTApiKey         string
	DisableIntegrity bool
	ExcludePathParts []string
	ExcludeGlobs     []string
	IncludeExt       map[string]struct{}
	ExcludeExt       map[string]struct{}
	Paranoid         bool
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
