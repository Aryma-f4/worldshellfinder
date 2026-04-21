package reporter

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Aryma-f4/worldshellfinder/internal/models"
	"github.com/pterm/pterm"
)

func PrintSingleDetection(detect *models.ShellDetection, verbose bool) {
	fmt.Print("\r")
	pterm.Warning.Printf("- File: %s\n", detect.Path)
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
	fmt.Println()
}

func PrintDetectionSummary(summary *models.ScanSummary, verbose bool) {
	pterm.DefaultSection.Println("WebShell Detection Summary")
	pterm.Info.Printf("Total files scanned: %d\n", summary.TotalFilesScanned)
	pterm.Info.Printf("Total potential webshells found: %d\n", len(summary.Detections))

	if len(summary.Detections) == 0 {
		pterm.Success.Println("No potential webshells were found.")
		return
	}
}

func escapeMarkdownTable(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "|", "\\|")
	return s
}

func WriteDetectionsToJSON(path string, summary *models.ScanSummary) error {
	b, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0644)
}

func WriteDetectionsToSARIF(path string, summary *models.ScanSummary) error {
	type SarifResult struct {
		RuleId  string `json:"ruleId"`
		Message struct {
			Text string `json:"text"`
		} `json:"message"`
		Locations []struct {
			PhysicalLocation struct {
				ArtifactLocation struct {
					Uri string `json:"uri"`
				} `json:"artifactLocation"`
				Region struct {
					StartLine int `json:"startLine"`
				} `json:"region"`
			} `json:"physicalLocation"`
		} `json:"locations"`
	}

	var results []SarifResult
	for _, d := range summary.Detections {
		for _, ev := range d.Evidences {
			line := ev.LineNumber
			if line < 1 {
				line = 1
			}
			res := SarifResult{
				RuleId: ev.Name,
			}
			res.Message.Text = fmt.Sprintf("Score: %d. Confidence: %s. %s", d.Score, d.Confidence, ev.Matched)
			res.Locations = append(res.Locations, struct {
				PhysicalLocation struct {
					ArtifactLocation struct {
						Uri string `json:"uri"`
					} `json:"artifactLocation"`
					Region struct {
						StartLine int `json:"startLine"`
					} `json:"region"`
				} `json:"physicalLocation"`
			}{
				PhysicalLocation: struct {
					ArtifactLocation struct {
						Uri string `json:"uri"`
					} `json:"artifactLocation"`
					Region struct {
						StartLine int `json:"startLine"`
					} `json:"region"`
				}{
					ArtifactLocation: struct {
						Uri string `json:"uri"`
					}{
						Uri: filepath.ToSlash(d.Path),
					},
					Region: struct {
						StartLine int `json:"startLine"`
					}{
						StartLine: line,
					},
				},
			})
			results = append(results, res)
		}
	}

	sarif := map[string]interface{}{
		"version": "2.1.0",
		"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		"runs": []interface{}{
			map[string]interface{}{
				"tool": map[string]interface{}{
					"driver": map[string]interface{}{
						"name":    "WorldShellFinder",
						"version": "3.5.0",
					},
				},
				"results": results,
			},
		},
	}

	b, err := json.MarshalIndent(sarif, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0644)
}

func WriteDetectionsToMarkdown(path string, summary *models.ScanSummary) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	w := bufio.NewWriter(file)
	fmt.Fprintln(w, "# WorldShellFinder Report")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "- Generated: %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Fprintf(w, "- Total files scanned: %d\n", summary.TotalFilesScanned)
	fmt.Fprintf(w, "- Total potential webshells found: %d\n", len(summary.Detections))
	fmt.Fprintln(w)

	if len(summary.Detections) == 0 {
		fmt.Fprintln(w, "No potential webshells were found.")
		fmt.Fprintln(w)
		return w.Flush()
	}

	fmt.Fprintln(w, "## Detections")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "| # | File | Score | Confidence |")
	fmt.Fprintln(w, "|---:|------|------:|------------|")
	for i, d := range summary.Detections {
		conf := d.Confidence
		if conf == "" {
			conf = "unknown"
		}
		fmt.Fprintf(w, "| %d | %s | %d | %s |\n", i+1, escapeMarkdownTable(d.Path), d.Score, strings.ToUpper(conf))
	}
	fmt.Fprintln(w)

	for i, d := range summary.Detections {
		fmt.Fprintf(w, "### #%d\n\n", i+1)
		fmt.Fprintf(w, "- File: %s\n", d.Path)
		fmt.Fprintf(w, "- Score: %d\n", d.Score)
		if d.Confidence != "" {
			fmt.Fprintf(w, "- Confidence: %s\n", strings.ToUpper(d.Confidence))
		}
		fmt.Fprintln(w)
		if len(d.Evidences) > 0 {
			fmt.Fprintln(w, "| Kind | Weight | Line | Name | Matched |")
			fmt.Fprintln(w, "|------|-------:|-----:|------|---------|")
			for _, ev := range d.Evidences {
				m := ev.Matched
				if m == "" {
					m = "-"
				}
				fmt.Fprintf(w, "| %s | %d | %d | %s | %s |\n", escapeMarkdownTable(ev.Kind), ev.Weight, ev.LineNumber, escapeMarkdownTable(ev.Name), escapeMarkdownTable(m))
			}
			fmt.Fprintln(w)
		}
	}

	return w.Flush()
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

func WriteDeepScanToMarkdown(path string, summary *models.DeepScanSummary) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	fmt.Fprintln(writer, "# WorldShellFinder Deep Scan Report")
	fmt.Fprintln(writer)
	fmt.Fprintf(writer, "- Generated: %s\n\n", time.Now().Format("2006-01-02 15:04:05"))

	if summary.FileSummary != nil {
		fmt.Fprintln(writer, "## File Detections")
		fmt.Fprintf(writer, "- Total files scanned: %d\n", summary.FileSummary.TotalFilesScanned)
		fmt.Fprintf(writer, "- Potential webshells found: %d\n", len(summary.FileSummary.Detections))
		fmt.Fprintln(writer)
		if len(summary.FileSummary.Detections) > 0 {
			fmt.Fprintln(writer, "| # | File | Score |")
			fmt.Fprintln(writer, "|---:|------|------:|")
			for i, detect := range summary.FileSummary.Detections {
				fmt.Fprintf(writer, "| %d | %s | %d |\n", i+1, escapeMarkdownTable(detect.Path), detect.Score)
			}
			fmt.Fprintln(writer)
		}
	}

	writeSystemFindingsMarkdown(writer, "Suspicious Traffic", summary.TrafficFindings)
	writeSystemFindingsMarkdown(writer, "Suspicious Logs", summary.LogFindings)
	writeSystemFindingsMarkdown(writer, "Rootkit Findings", summary.RootkitFindings)

	fmt.Fprintln(writer, "## Warnings")
	if len(summary.Warnings) > 0 {
		for _, warning := range summary.Warnings {
			fmt.Fprintf(writer, "- %s\n", warning)
		}
	} else {
		fmt.Fprintln(writer, "- No warnings")
	}
	fmt.Fprintln(writer)

	return writer.Flush()
}

func writeSystemFindingsMarkdown(writer *bufio.Writer, title string, findings []models.SystemFinding) {
	fmt.Fprintf(writer, "## %s\n", title)
	if len(findings) == 0 {
		fmt.Fprintln(writer, "- No findings in this section")
	} else {
		for _, finding := range findings {
			fmt.Fprintf(writer, "### %s\n", finding.Title)
			fmt.Fprintf(writer, "- **Severity:** %s\n", strings.ToUpper(finding.Severity))
			fmt.Fprintf(writer, "- **Detail:** %s\n", finding.Detail)
			fmt.Fprintln(writer)
		}
	}
	fmt.Fprintln(writer)
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

func WriteDeepScanToJSON(path string, summary *models.DeepScanSummary) error {
	b, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0644)
}

func WriteDeepScanToSARIF(path string, summary *models.DeepScanSummary) error {
	// DeepScan has multiple parts, but SARIF is mostly for static files.
	// We'll just serialize the file findings for SARIF.
	if summary.FileSummary != nil {
		return WriteDetectionsToSARIF(path, summary.FileSummary)
	}
	return nil
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
