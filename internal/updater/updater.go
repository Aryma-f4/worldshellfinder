package updater

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
)

func UpdateFromRepository(repoURL string) error {
	osType := runtime.GOOS
	archType := runtime.GOARCH
	downloadURL := fmt.Sprintf("https://%s/releases/latest/download/%s_%s", repoURL, osType, archType)
	fmt.Printf("Downloading update from: %s\n", downloadURL)

	tmpFile, err := os.CreateTemp("", "worldshellfinder_*")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	defer tmpFile.Close()

	resp, err := http.Get(downloadURL)
	if err != nil {
		return fmt.Errorf("failed to download update: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download update: HTTP %d", resp.StatusCode)
	}

	if _, err = io.Copy(tmpFile, resp.Body); err != nil {
		return fmt.Errorf("failed to write update to file: %w", err)
	}

	executablePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get current executable path: %w", err)
	}

	if err = os.Rename(tmpFile.Name(), executablePath); err != nil {
		return fmt.Errorf("failed to replace current binary: %w", err)
	}

	if err = os.Chmod(executablePath, 0755); err != nil {
		return fmt.Errorf("failed to make new binary executable: %w", err)
	}

	fmt.Println("Update complete! Restarting the application...")

	cmd := exec.Command(executablePath)
	if err = cmd.Start(); err != nil {
		return fmt.Errorf("failed to restart application: %w", err)
	}
	os.Exit(0)
	return nil
}
