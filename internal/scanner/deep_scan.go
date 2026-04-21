package scanner

import (
	"embed"
	"fmt"
	"strings"

	"github.com/Aryma-f4/worldshellfinder/internal/models"
	"github.com/Aryma-f4/worldshellfinder/internal/reporter"
	"github.com/Aryma-f4/worldshellfinder/internal/utils"
	"github.com/pterm/pterm"
)

func RunDeepScan(directories []string, wordlistPath, outputFile string, minScore, maxEvidence int, vtApiKey string, opts RuntimeOptions, defaultWordlist embed.FS) error {
	cfg, err := BuildScanConfig(wordlistPath, minScore, maxEvidence, vtApiKey, opts, defaultWordlist)
	if err != nil {
		return err
	}

	done := make(chan bool)
	go utils.LoadingAnimation(done)
	fileSummary, err := ScanDirectories(directories, cfg, opts.Verbose, opts.NumWorkers)
	if err != nil {
		done <- true
		fmt.Print("\rOperation complete!                          \n")
		return err
	}
	trafficFindings, trafficWarnings := RunTrafficScan()
	logFindings, logWarnings := RunLogScan()
	rootkitFindings, rootkitWarnings := RunRootkitScan()
	done <- true
	fmt.Print("\rOperation complete!                          \n")

	warnings := append([]string{}, trafficWarnings...)
	for _, warning := range logWarnings {
		warnings = utils.AppendUnique(warnings, warning)
	}
	for _, warning := range rootkitWarnings {
		warnings = utils.AppendUnique(warnings, warning)
	}

	summary := &models.DeepScanSummary{
		FileSummary:     fileSummary,
		TrafficFindings: trafficFindings,
		LogFindings:     logFindings,
		RootkitFindings: rootkitFindings,
		Warnings:        warnings,
	}

	pterm.DefaultSection.Println("Deep Scan Summary")
	reporter.PrintDetectionSummary(fileSummary, opts.Verbose)
	reporter.PrintSystemFindings("Suspicious Traffic", trafficFindings)
	reporter.PrintSystemFindings("Suspicious Logs", logFindings)
	reporter.PrintSystemFindings("Rootkit Findings", rootkitFindings)
	reporter.PrintWarnings(warnings)

	if outputFile != "" {
		lowerOut := strings.ToLower(outputFile)
		if strings.HasSuffix(lowerOut, ".md") || strings.HasSuffix(lowerOut, ".markdown") {
			if err := reporter.WriteDeepScanToMarkdown(outputFile, summary); err != nil {
				return fmt.Errorf("error writing deep scan output: %w", err)
			}
		} else if strings.HasSuffix(lowerOut, ".json") {
			if err := reporter.WriteDeepScanToJSON(outputFile, summary); err != nil {
				return fmt.Errorf("error writing deep scan output: %w", err)
			}
		} else if strings.HasSuffix(lowerOut, ".sarif") {
			if err := reporter.WriteDeepScanToSARIF(outputFile, summary); err != nil {
				return fmt.Errorf("error writing deep scan output: %w", err)
			}
		} else {
			if err := reporter.WriteDeepScanToFile(outputFile, summary); err != nil {
				return fmt.Errorf("error writing deep scan output: %w", err)
			}
		}
		pterm.Success.Printf("Results have been saved to: %s\n", outputFile)
	}

	return nil
}
