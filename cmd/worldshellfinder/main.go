package main

import (
	"bufio"
	"embed"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/Aryma-f4/worldshellfinder/internal/config"
	"github.com/Aryma-f4/worldshellfinder/internal/remover"
	"github.com/Aryma-f4/worldshellfinder/internal/scanner"
	"github.com/Aryma-f4/worldshellfinder/internal/updater"
	"github.com/pterm/pterm"
)

//go:embed wordlists/*
var defaultWordlist embed.FS

var verbose bool

func readDirectoryListFile(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var directories []string
	s := bufio.NewScanner(file)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			continue
		}
		directories = append(directories, line)
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	return directories, nil
}

func main() {
	helpFlag := flag.Bool("h", false, "display help information")
	helpFlagLong := flag.Bool("help", false, "display help information")
	updateFlag := flag.Bool("update", false, "update latest version from repository")
	verboseFlag := flag.Bool("v", false, "enable verbose mode")
	noIntegrityFlag := flag.Bool("no-integrity", false, "disable core file integrity verification")
	modeFlag := flag.String("mode", "", "operation mode: detect, deep, or remove")
	dirFlag := flag.String("dir", "", "directory to scan")
	dirListFlag := flag.String("dir-list", "", "file containing a list of directories to scan (one per line)")
	outFlag := flag.String("out", "", "output file path")
	wordlistFlag := flag.String("wordlist", "", "custom wordlist path")
	minScoreFlag := flag.Int("min-score", config.DefaultMinScore, "minimum score before reporting a file")
	maxEvidenceFlag := flag.Int("max-evidence", config.DefaultMaxEvidence, "maximum evidence entries shown per file")
	removeStringFlag := flag.String("remove-string", "", "string to remove in remove mode")
	vtApiKeyFlag := flag.String("vt-api-key", "", "VirusTotal API key for malware reference database")
	workersFlag := flag.Int("workers", runtime.NumCPU(), "number of concurrent workers for scanning files")
	flag.Parse()

	verbose = *verboseFlag
	fmt.Print(config.Banner)

	if *helpFlag || *helpFlagLong {
		printHelp()
		return
	}

	if *updateFlag {
		pterm.Info.Println("Checking for updates...")
		if err := updater.UpdateFromRepository("github.com/Aryma-f4/worldshellfinder"); err != nil {
			pterm.Fatal.Printf("Error While Updating: %v\n", err)
		}
		pterm.Success.Println("Update done.")
		return
	}

	if *minScoreFlag < 1 {
		pterm.Fatal.Println("min-score must be at least 1")
	}
	if *maxEvidenceFlag < 1 {
		pterm.Fatal.Println("max-evidence must be at least 1")
	}

	reader := bufio.NewReader(os.Stdin)
	mode := strings.TrimSpace(strings.ToLower(*modeFlag))
	directory := strings.TrimSpace(*dirFlag)
	dirListPath := strings.TrimSpace(*dirListFlag)
	outputFile := strings.TrimSpace(*outFlag)
	vtApiKey := strings.TrimSpace(*vtApiKeyFlag)
	wordlistPath := strings.TrimSpace(*wordlistFlag)

	if mode != "" {
		var directories []string
		if dirListPath != "" {
			paths, err := readDirectoryListFile(dirListPath)
			if err != nil {
				pterm.Fatal.Printf("Failed reading dir-list file: %v\n", err)
			}
			directories = append(directories, paths...)
		}
		if directory != "" {
			directories = append(directories, directory)
		}
		if len(directories) == 0 {
			pterm.Fatal.Println("dir or dir-list is required when mode is provided")
		}
		switch mode {
		case "detect":
			if err := scanner.RunDetection(directories, wordlistPath, outputFile, *minScoreFlag, *maxEvidenceFlag, vtApiKey, *noIntegrityFlag, verbose, defaultWordlist, *workersFlag); err != nil {
				pterm.Fatal.Printf("Detection failed: %v\n", err)
			}
		case "deep":
			if err := scanner.RunDeepScan(directories, wordlistPath, outputFile, *minScoreFlag, *maxEvidenceFlag, vtApiKey, *noIntegrityFlag, verbose, defaultWordlist, *workersFlag); err != nil {
				pterm.Fatal.Printf("Deep scan failed: %v\n", err)
			}
		case "remove":
			if err := remover.RunRemoval(directories, outputFile, reader, *removeStringFlag, verbose, *workersFlag); err != nil {
				pterm.Fatal.Printf("String removal failed: %v\n", err)
			}
		default:
			pterm.Fatal.Printf("invalid mode %q, use detect, deep, or remove\n", mode)
		}
		return
	}

	// Interactive Mode
	pterm.DefaultHeader.WithFullWidth().WithBackgroundStyle(pterm.NewStyle(pterm.BgCyan)).WithTextStyle(pterm.NewStyle(pterm.FgBlack)).Println("World Shell Finder - Interactive Mode")

	options := []string{
		"1. Normal WebShell Detection",
		"2. Remove String from Files",
		"3. Deep Scan (files, traffic, rootkit)",
	}
	choice, _ := pterm.DefaultInteractiveSelect.WithOptions(options).Show("Please choose an operation mode")

	if directory == "" {
		directory, _ = pterm.DefaultInteractiveTextInput.Show("Enter the directory to scan")
		directory = strings.TrimSpace(directory)
		if directory == "" {
			pterm.Fatal.Println("Directory cannot be empty")
		}
	}

	if outputFile == "" {
		outputFile, _ = pterm.DefaultInteractiveTextInput.Show("Enter the output file path (press Enter for no file output)")
		outputFile = strings.TrimSpace(outputFile)
	}

	switch choice {
	case "1. Normal WebShell Detection":
		if wordlistPath == "" {
			wordlistPath, _ = pterm.DefaultInteractiveTextInput.Show("Enter custom wordlist path (press Enter to skip)")
			wordlistPath = strings.TrimSpace(wordlistPath)
		}
		if vtApiKey == "" {
			vtApiKey, _ = pterm.DefaultInteractiveTextInput.Show("Enter VirusTotal API Key (press Enter to skip)")
			vtApiKey = strings.TrimSpace(vtApiKey)
		}
		err := scanner.RunDetection([]string{directory}, wordlistPath, outputFile, *minScoreFlag, *maxEvidenceFlag, vtApiKey, *noIntegrityFlag, verbose, defaultWordlist, *workersFlag)
		if err != nil {
			pterm.Fatal.Printf("Detection failed: %v\n", err)
		}
	case "2. Remove String from Files":
		err := remover.RunRemoval([]string{directory}, outputFile, reader, *removeStringFlag, verbose, *workersFlag)
		if err != nil {
			pterm.Fatal.Printf("String removal failed: %v\n", err)
		}
	case "3. Deep Scan (files, traffic, rootkit)":
		if wordlistPath == "" {
			wordlistPath, _ = pterm.DefaultInteractiveTextInput.Show("Enter custom wordlist path (press Enter to skip)")
			wordlistPath = strings.TrimSpace(wordlistPath)
		}
		if vtApiKey == "" {
			vtApiKey, _ = pterm.DefaultInteractiveTextInput.Show("Enter VirusTotal API Key (press Enter to skip)")
			vtApiKey = strings.TrimSpace(vtApiKey)
		}
		err := scanner.RunDeepScan([]string{directory}, wordlistPath, outputFile, *minScoreFlag, *maxEvidenceFlag, vtApiKey, *noIntegrityFlag, verbose, defaultWordlist, *workersFlag)
		if err != nil {
			pterm.Fatal.Printf("Deep scan failed: %v\n", err)
		}
	default:
		pterm.Error.Println("Invalid choice!")
	}
}

func printHelp() {
	fmt.Println("Usage:")
	fmt.Println("  worldshellfinder -mode detect -dir <directory> [options]")
	fmt.Println("  worldshellfinder -mode detect -dir-list <file> [options]")
	fmt.Println("  worldshellfinder -mode deep -dir <directory> [options]")
	fmt.Println("  worldshellfinder -mode deep -dir-list <file> [options]")
	fmt.Println("  worldshellfinder -mode remove -dir <directory> -remove-string <value> [options]")
	fmt.Println("  worldshellfinder -mode remove -dir-list <file> -remove-string <value> [options]")
	fmt.Println("  worldshellfinder")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  -h, --help              Show help information")
	fmt.Println("  -v                      Enable verbose output")
	fmt.Println("  -mode string            Operation mode: detect, deep, or remove")
	fmt.Println("  -dir string             Directory to scan")
	fmt.Println("  -dir-list string        File containing a list of directories to scan (one per line)")
	fmt.Println("  -out string             Output file path")
	fmt.Println("  -wordlist string        Additional custom wordlist file")
	fmt.Println("  -min-score int          Minimum score before a file is reported (default: 4)")
	fmt.Println("  -max-evidence int       Maximum evidence entries shown per file (default: 5)")
	fmt.Println("  -remove-string string   String to remove when mode=remove")
	fmt.Println("  -vt-api-key string      VirusTotal API key for checking suspicious files")
	fmt.Println("  -workers int            Number of concurrent workers for scanning files (default: number of CPUs)")
	fmt.Println("  -no-integrity           Disable Core File Integrity Verification (skip API checksum checks)")
	fmt.Println("  --update                Update to the latest release")
}
