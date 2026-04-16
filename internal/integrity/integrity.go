package integrity

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"github.com/pterm/pterm"
)

var (
	dirRootCache   = make(map[string]string)
	dirRootCacheMu sync.RWMutex

	wpVersions   = make(map[string]string)
	wpVersionsMu sync.RWMutex

	wpChecksums   = make(map[string]map[string]string)
	wpChecksumsMu sync.RWMutex

	versionRegex = regexp.MustCompile(`\$wp_version\s*=\s*['"]([^'"]+)['"]`)
)

type CheckResult int

const (
	ResultUnknown CheckResult = iota
	ResultMatch
	ResultModified
)

func getWPRoot(filePath string) (string, string) {
	dir := filepath.Dir(filePath)

	dirRootCacheMu.RLock()
	cachedRoot, cached := dirRootCache[dir]
	dirRootCacheMu.RUnlock()

	if cached {
		if cachedRoot == "" {
			return "", ""
		}
		wpVersionsMu.RLock()
		ver := wpVersions[cachedRoot]
		wpVersionsMu.RUnlock()
		return cachedRoot, ver
	}

	currentDir := dir
	var root string
	var version string

	for {
		versionFile := filepath.Join(currentDir, "wp-includes", "version.php")
		if _, err := os.Stat(versionFile); err == nil {
			b, err := os.ReadFile(versionFile)
			if err == nil {
				m := versionRegex.FindStringSubmatch(string(b))
				if len(m) > 1 {
					root = currentDir
					version = m[1]
					break
				}
			}
		}
		parent := filepath.Dir(currentDir)
		if parent == currentDir {
			break
		}
		currentDir = parent
	}

	dirRootCacheMu.Lock()
	dirRootCache[dir] = root
	dirRootCacheMu.Unlock()

	if root != "" {
		wpVersionsMu.Lock()
		wpVersions[root] = version
		wpVersionsMu.Unlock()
	}

	return root, version
}

func fetchWPChecksums(version string) (map[string]string, error) {
	url := fmt.Sprintf("https://api.wordpress.org/core/checksums/1.0/?version=%s&locale=en_US", version)
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var data struct {
		Checksums map[string]string `json:"checksums"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}
	if len(data.Checksums) == 0 {
		return nil, fmt.Errorf("no checksums")
	}
	return data.Checksums, nil
}

func CheckCoreFile(filePath string) (CheckResult, string) {
	root, version := getWPRoot(filePath)
	if root == "" || version == "" {
		return ResultUnknown, ""
	}

	wpChecksumsMu.RLock()
	checksums, ok := wpChecksums[version]
	wpChecksumsMu.RUnlock()

	if !ok {
		wpChecksumsMu.Lock()
		checksums, ok = wpChecksums[version]
		if !ok {
			pterm.Info.Printf("\rFetching WordPress %s checksums from API...      \n", version)
			fetched, err := fetchWPChecksums(version)
			if err == nil {
				wpChecksums[version] = fetched
				checksums = fetched
			} else {
				wpChecksums[version] = map[string]string{}
				checksums = wpChecksums[version]
			}
		}
		wpChecksumsMu.Unlock()
	}

	if len(checksums) == 0 {
		return ResultUnknown, ""
	}

	relPath, err := filepath.Rel(root, filePath)
	if err != nil {
		return ResultUnknown, ""
	}
	relPath = filepath.ToSlash(relPath)

	expectedMD5, exists := checksums[relPath]
	if !exists {
		return ResultUnknown, ""
	}

	f, err := os.Open(filePath)
	if err != nil {
		return ResultUnknown, ""
	}
	defer f.Close()

	h := md5.New()
	if _, err := io.Copy(h, f); err != nil {
		return ResultUnknown, ""
	}
	actualMD5 := hex.EncodeToString(h.Sum(nil))

	if actualMD5 == expectedMD5 {
		return ResultMatch, "WordPress"
	}
	return ResultModified, "WordPress"
}
