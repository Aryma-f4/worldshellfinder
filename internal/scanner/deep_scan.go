package scanner

import (
	"embed"
	"fmt"

	"github.com/Aryma-f4/worldshellfinder/internal/models"
	"github.com/Aryma-f4/worldshellfinder/internal/reporter"
	"github.com/Aryma-f4/worldshellfinder/internal/utils"
	"github.com/pterm/pterm"
)

func RunDeepScan(directory, wordlistPath, outputFile string, minScore, maxEvidence int, vtApiKey string, verbose bool, defaultWordlist embed.FS, numWorkers int) error {
	cfg, err := BuildScanConfig(wordlistPath, minScore, maxEvidence, vtApiKey, defaultWordlist)
	if err != nil {
		return err
	}

	done := make(chan bool)
	go utils.LoadingAnimation(done)
	fileSummary, err := ScanDirectory(directory, cfg, verbose, numWorkers)
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
	reporter.PrintDetectionSummary(fileSummary, verbose)
	reporter.PrintSystemFindings("Suspicious Traffic", trafficFindings)
	reporter.PrintSystemFindings("Suspicious Logs", logFindings)
	reporter.PrintSystemFindings("Rootkit Findings", rootkitFindings)
	reporter.PrintWarnings(warnings)

	if outputFile != "" {
		if err := reporter.WriteDeepScanToFile(outputFile, summary); err != nil {
			return fmt.Errorf("error writing deep scan output: %w", err)
		}
		pterm.Success.Printf("Results have been saved to: %s\n", outputFile)
	}

	return nil
}
