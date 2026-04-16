import os

def replace_in_file(file_path, old_str, new_str):
    with open(file_path, 'r') as f:
        content = f.read()
    if old_str in content:
        content = content.replace(old_str, new_str)
        with open(file_path, 'w') as f:
            f.write(content)
        print(f"Updated {file_path}")
    else:
        print(f"Could not find old_str in {file_path}")

# 1. Update internal/scanner/scanner.go
scanner_old_walk = """	err := filepath.Walk(directory, func(path string, info os.FileInfo, walkErr error) error {
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

	if err != nil {
		return nil, err
	}"""

scanner_new_walk = """	for _, dir := range directories {
		err := filepath.Walk(dir, func(path string, info os.FileInfo, walkErr error) error {
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
		if err != nil {
			close(fileChan)
			wg.Wait()
			return nil, err
		}
	}
	
	close(fileChan)
	wg.Wait()"""

replace_in_file('internal/scanner/scanner.go', 
    'func ScanDirectory(directory string, cfg models.ScanConfig, verbose bool, numWorkers int) (*models.ScanSummary, error) {', 
    'func ScanDirectories(directories []string, cfg models.ScanConfig, verbose bool, numWorkers int) (*models.ScanSummary, error) {')

replace_in_file('internal/scanner/scanner.go', scanner_old_walk, scanner_new_walk)

replace_in_file('internal/scanner/scanner.go', 
    'func RunDetection(directory, wordlistPath, outputFile string, minScore, maxEvidence int, vtApiKey string, verbose bool, defaultWordlist embed.FS, numWorkers int) error {', 
    'func RunDetection(directories []string, wordlistPath, outputFile string, minScore, maxEvidence int, vtApiKey string, verbose bool, defaultWordlist embed.FS, numWorkers int) error {')

replace_in_file('internal/scanner/scanner.go', 
    'summary, err := ScanDirectory(directory, cfg, verbose, numWorkers)', 
    'summary, err := ScanDirectories(directories, cfg, verbose, numWorkers)')

# 2. Update internal/scanner/deep_scan.go
replace_in_file('internal/scanner/deep_scan.go', 
    'func RunDeepScan(directory, wordlistPath, outputFile string, minScore, maxEvidence int, vtApiKey string, verbose bool, defaultWordlist embed.FS, numWorkers int) error {', 
    'func RunDeepScan(directories []string, wordlistPath, outputFile string, minScore, maxEvidence int, vtApiKey string, verbose bool, defaultWordlist embed.FS, numWorkers int) error {')

replace_in_file('internal/scanner/deep_scan.go', 
    'fileSummary, err := ScanDirectory(directory, cfg, verbose, numWorkers)', 
    'fileSummary, err := ScanDirectories(directories, cfg, verbose, numWorkers)')

# 3. Update internal/remover/remover.go
remover_old_walk = """	err := filepath.Walk(directory, func(path string, info os.FileInfo, walkErr error) error {
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
	fmt.Print("\\rOperation complete!                          \\n")
	if err != nil {
		return err
	}"""

remover_new_walk = """	for _, dir := range directories {
		err := filepath.Walk(dir, func(path string, info os.FileInfo, walkErr error) error {
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
		if err != nil {
			close(fileChan)
			wg.Wait()
			done <- true
			fmt.Print("\\rOperation complete!                          \\n")
			return err
		}
	}
	
	close(fileChan)
	wg.Wait()

	done <- true
	fmt.Print("\\rOperation complete!                          \\n")"""

replace_in_file('internal/remover/remover.go', 
    'func RunRemoval(directory, outputFile string, reader *bufio.Reader, removeValue string, verbose bool, numWorkers int) error {', 
    'func RunRemoval(directories []string, outputFile string, reader *bufio.Reader, removeValue string, verbose bool, numWorkers int) error {')

replace_in_file('internal/remover/remover.go', remover_old_walk, remover_new_walk)

