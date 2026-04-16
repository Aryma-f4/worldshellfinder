package remover

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"sync"
	"sync/atomic"

	"github.com/Aryma-f4/worldshellfinder/internal/models"
	"github.com/Aryma-f4/worldshellfinder/internal/reporter"
	"github.com/Aryma-f4/worldshellfinder/internal/utils"
	"github.com/pterm/pterm"
)

func removeStringFromFile(filePath string, stringToRemove string) (*models.FileModification, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	originalSize := int64(len(content))
	originalContent := string(content)
	stringsRemoved := strings.Count(originalContent, stringToRemove)
	if stringsRemoved == 0 {
		return nil, nil
	}

	newContent := strings.ReplaceAll(originalContent, stringToRemove, "")
	if err = os.WriteFile(filePath, []byte(newContent), 0644); err != nil {
		return nil, err
	}

	return &models.FileModification{
		Path:           filePath,
		OriginalSize:   originalSize,
		ModifiedSize:   int64(len(newContent)),
		StringsRemoved: stringsRemoved,
	}, nil
}

func RunRemoval(directory, outputFile string, reader *bufio.Reader, removeValue string, verbose bool, numWorkers int) error {
	stringToRemove := strings.TrimSpace(removeValue)
	if stringToRemove == "" {
		pterm.Info.Println("Enter string to remove (press Ctrl+D or Ctrl+Z when done):")

		largeBuffer := make([]byte, 10*1024*1024)
		var totalSize int64
		maxSize := int64(10 * 1024 * 1024)
		var builder strings.Builder
		builder.Grow(len(largeBuffer))

		for {
			n, err := reader.Read(largeBuffer)
			if err == io.EOF {
				break
			}
			if err != nil {
				return fmt.Errorf("error reading input: %w", err)
			}
			totalSize += int64(n)
			if totalSize > maxSize {
				return fmt.Errorf("input exceeds maximum size of 10MB")
			}
			builder.Write(largeBuffer[:n])
		}

		stringToRemove = strings.TrimSpace(builder.String())
	}

	if stringToRemove == "" {
		return fmt.Errorf("empty string provided")
	}

	fmt.Printf("String size to remove: %.2f MB\n", float64(len(stringToRemove))/(1024*1024))

	var modifications []*models.FileModification
	var totalFilesScanned int32
	var totalStringsRemoved int32
	var mu sync.Mutex

	done := make(chan bool)
	go utils.LoadingAnimation(done)

	fileChan := make(chan string, 1000)
	var wg sync.WaitGroup

	if numWorkers <= 0 {
		numWorkers = 1
	}

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range fileChan {
				atomic.AddInt32(&totalFilesScanned, 1)
				modification, err := removeStringFromFile(path, stringToRemove)
				if err != nil {
					utils.LogReadIssue(path, err)
					continue
				}
				if modification != nil {
					mu.Lock()
					modifications = append(modifications, modification)
					mu.Unlock()
					atomic.AddInt32(&totalStringsRemoved, int32(modification.StringsRemoved))
				}
				if verbose {
					pterm.Info.Printf("Processed file: %s\n", path)
				}
			}
		}()
	}

	err := filepath.Walk(directory, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			utils.LogWalkIssue(path, walkErr)
			return nil
		}
		if info.IsDir() {
			return nil
		}
		fileChan <- path
		return nil
	})
	
	close(fileChan)
	wg.Wait()

	done <- true
	fmt.Print("\rOperation complete!                          \n")
	if err != nil {
		return err
	}

	pterm.DefaultSection.Println("String Removal Summary")
	pterm.Info.Printf("Total files scanned: %d\n", totalFilesScanned)
	pterm.Info.Printf("Total files modified: %d\n", len(modifications))
	pterm.Info.Printf("Total strings removed: %d\n", totalStringsRemoved)

	if outputFile != "" {
		if err := reporter.WriteModificationsToFile(outputFile, modifications, int(totalFilesScanned), int(totalStringsRemoved)); err != nil {
			return fmt.Errorf("error writing to output file: %w", err)
		}
		pterm.Success.Printf("Results have been saved to: %s\n", outputFile)
	}

	return nil
}
