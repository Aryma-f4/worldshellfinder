package reporter

import (
	"bufio"
	"fmt"
	"os"
	"time"
	"strings"

	"github.com/Aryma-f4/worldshellfinder/internal/models"
	"github.com/pterm/pterm"
)

func PrintDetectionSummary(summary *models.ScanSummary, verbose bool) {
	pterm.DefaultSection.Println("WebShell Detection Summary")
	pterm.Info.Printf("Total files scanned: %d\n", summary.TotalFilesScanned)
	pterm.Info.Printf("Total potential webshells found: %d\n", len(summary.Detections))

	if len(summary.Detections) == 0 {
		pterm.Success.Println("No potential webshells were found.")
		return
	}

	pterm.Error.Println("Potential WebShells Found:")
	for _, detect := range summary.Detections {
		pterm.Warning.Printf("\n- File: %s\n", detect.Path)
		pterm.Warning.Printf("  Suspicion score: %d\n", detect.Score)
		for _, evidence := range detect.Evidences {
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

func WriteDetectionsToFile(path string, summary *models.ScanSummary) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	fmt.Fprintln(writer, "WebShell Detection Report")
	fmt.Fprintf(writer, "Generated: %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Fprintf(writer, "Total files scanned: %d\n", summary.TotalFilesScanned)
	fmt.Fprintf(writer, "Total potential webshells found: %d\n\n", len(summary.Detections))

	for i, detect := range summary.Detections {
		fmt.Fprintf(writer, "Detection #%d:\n", i+1)
		fmt.Fprintf(writer, "- File: %s\n", detect.Path)
		fmt.Fprintf(writer, "- Suspicion score: %d\n", detect.Score)
		for _, evidence := range detect.Evidences {
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

func WriteModificationsToFile(filepath string, modifications []*models.FileModification, totalFilesScanned int, totalStringsRemoved int) error {
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
		fmt.Fprintf(writer, "- File: %s\n", mod.Path)
		fmt.Fprintf(writer, "- Strings removed: %d\n", mod.StringsRemoved)
		fmt.Fprintf(writer, "- Original size: %d bytes\n", mod.OriginalSize)
		fmt.Fprintf(writer, "- Modified size: %d bytes\n", mod.ModifiedSize)
		fmt.Fprintf(writer, "- Size difference: %d bytes\n\n", mod.OriginalSize-mod.ModifiedSize)
	}

	return writer.Flush()
}

func PrintSystemFindings(title string, findings []models.SystemFinding) {
	pterm.DefaultSection.Println(title)
	if len(findings) == 0 {
		pterm.Success.Println("No findings in this section.")
		return
	}
	for _, finding := range findings {
		if strings.ToLower(finding.Severity) == "high" {
			pterm.Error.Printf("- [%s] %s\n  %s\n", strings.ToUpper(finding.Severity), finding.Title, finding.Detail)
		} else {
			pterm.Warning.Printf("- [%s] %s\n  %s\n", strings.ToUpper(finding.Severity), finding.Title, finding.Detail)
		}
	}
}

func PrintWarnings(warnings []string) {
	if len(warnings) == 0 {
		return
	}
	pterm.DefaultSection.Println("Warnings")
	for _, warning := range warnings {
		pterm.Warning.Println("- " + warning)
	}
}

func WriteDeepScanToFile(path string, summary *models.DeepScanSummary) error {
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
		fmt.Fprintf(writer, "Total files scanned: %d\n", summary.FileSummary.TotalFilesScanned)
		fmt.Fprintf(writer, "Potential webshells found: %d\n", len(summary.FileSummary.Detections))
		for _, detect := range summary.FileSummary.Detections {
			fmt.Fprintf(writer, "- %s (score: %d)\n", detect.Path, detect.Score)
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
