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
	"runtime"
	"strings"
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

	wpPluginChecksums   = make(map[string]map[string]string) // key: "pluginSlug:version" -> map[file]md5
	wpPluginChecksumsMu sync.RWMutex

	frameworkRoots   = make(map[string]string)
	frameworkRootsMu sync.RWMutex

	versionRegex       = regexp.MustCompile(`\$wp_version\s*=\s*['"]([^'"]+)['"]`)
	pluginVersionRegex = regexp.MustCompile(`(?i)Version:\s*([0-9\.]+)`)

	cacheOnce   sync.Once
	cacheMu     sync.Mutex
	checksumTTL = 24 * time.Hour
)

type checksumEntry struct {
	FetchedAt int64             `json:"fetched_at"`
	Checksums map[string]string `json:"checksums"`
}

type checksumDiskCache struct {
	Core    map[string]checksumEntry `json:"core"`
	Plugins map[string]checksumEntry `json:"plugins"`
}

type CheckResult int

const (
	ResultUnknown CheckResult = iota
	ResultMatch
	ResultModified
)

var apiLimiter = time.NewTicker(350 * time.Millisecond)

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

func cacheFilePath() string {
	dir, err := os.UserCacheDir()
	if err != nil || dir == "" {
		return ""
	}
	return filepath.Join(dir, "worldshellfinder", "wp_checksums.json")
}

func ensureCacheLoaded() {
	cacheOnce.Do(func() {
		p := cacheFilePath()
		if p == "" {
			return
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return
		}
		var data checksumDiskCache
		if err := json.Unmarshal(b, &data); err != nil {
			return
		}
		if data.Core == nil {
			data.Core = make(map[string]checksumEntry)
		}
		if data.Plugins == nil {
			data.Plugins = make(map[string]checksumEntry)
		}

		now := time.Now().Unix()
		for ver, entry := range data.Core {
			if entry.FetchedAt <= 0 || now-entry.FetchedAt > int64(checksumTTL.Seconds()) {
				continue
			}
			if len(entry.Checksums) > 0 {
				wpChecksums[ver] = entry.Checksums
			}
		}
		for key, entry := range data.Plugins {
			if entry.FetchedAt <= 0 || now-entry.FetchedAt > int64(checksumTTL.Seconds()) {
				continue
			}
			if len(entry.Checksums) > 0 {
				wpPluginChecksums[key] = entry.Checksums
			}
		}
	})
}

func saveCacheLocked() {
	p := cacheFilePath()
	if p == "" {
		return
	}
	_ = os.MkdirAll(filepath.Dir(p), 0o755)

	data := checksumDiskCache{
		Core:    make(map[string]checksumEntry),
		Plugins: make(map[string]checksumEntry),
	}

	now := time.Now().Unix()
	wpChecksumsMu.RLock()
	for ver, c := range wpChecksums {
		if len(c) == 0 {
			continue
		}
		data.Core[ver] = checksumEntry{FetchedAt: now, Checksums: c}
	}
	wpChecksumsMu.RUnlock()

	wpPluginChecksumsMu.RLock()
	for key, c := range wpPluginChecksums {
		if len(c) == 0 {
			continue
		}
		data.Plugins[key] = checksumEntry{FetchedAt: now, Checksums: c}
	}
	wpPluginChecksumsMu.RUnlock()

	b, err := json.Marshal(data)
	if err != nil {
		return
	}
	_ = os.WriteFile(p, b, 0o644)
}

func doGET(url string) (*http.Response, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	var lastErr error
	for attempt := 0; attempt < 4; attempt++ {
		<-apiLimiter.C
		resp, err := client.Get(url)
		if err == nil && resp != nil && resp.StatusCode == http.StatusOK {
			return resp, nil
		}
		if resp != nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode == http.StatusNotFound {
				return nil, fmt.Errorf("not found")
			}
		}
		if err != nil {
			lastErr = err
		} else {
			lastErr = fmt.Errorf("http status not ok")
		}
		time.Sleep(time.Duration(200*(attempt+1)) * time.Millisecond)
	}
	return nil, lastErr
}

func fetchWPChecksums(version string) (map[string]string, error) {
	url := fmt.Sprintf("https://api.wordpress.org/core/checksums/1.0/?version=%s&locale=en_US", version)
	resp, err := doGET(url)
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

func getBaselinePath(slug, version string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".cache", "worldshellfinder", "baselines")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}
	return filepath.Join(dir, fmt.Sprintf("%s-%s.json", slug, version)), nil
}

func loadLocalBaseline(slug, version string) (map[string]string, error) {
	path, err := getBaselinePath(slug, version)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var data map[string]string
	if err := json.Unmarshal(b, &data); err != nil {
		return nil, err
	}
	return data, nil
}

func SaveLocalBaseline(pluginDir string) error {
	_, slug, version := getWPPluginInfo(filepath.Join(pluginDir, "dummy.php"))
	if slug == "" || version == "" {
		return fmt.Errorf("could not determine plugin slug or version from %s", pluginDir)
	}

	checksums := make(map[string]string)
	err := filepath.Walk(pluginDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		relPath, err := filepath.Rel(pluginDir, path)
		if err != nil {
			return nil
		}
		relPath = filepath.ToSlash(relPath)

		f, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer f.Close()

		h := md5.New()
		if _, err := io.Copy(h, f); err != nil {
			return nil
		}
		checksums[relPath] = hex.EncodeToString(h.Sum(nil))
		return nil
	})

	if err != nil {
		return err
	}

	outPath, err := getBaselinePath(slug, version)
	if err != nil {
		return err
	}

	b, err := json.MarshalIndent(checksums, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(outPath, b, 0644); err != nil {
		return err
	}

	fmt.Printf("Baseline saved to %s (%d files)\n", outPath, len(checksums))
	return nil
}

func fetchWPPluginChecksums(pluginSlug, version string) (map[string]string, error) {
	url := fmt.Sprintf("https://downloads.wordpress.org/plugin-checksums/%s/%s.json", pluginSlug, version)
	resp, err := doGET(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var data struct {
		Files map[string]struct {
			MD5 string `json:"md5"`
		} `json:"files"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	checksums := make(map[string]string, len(data.Files))
	for file, hashes := range data.Files {
		if hashes.MD5 != "" {
			checksums[file] = hashes.MD5
		}
	}

	if len(checksums) == 0 {
		return nil, fmt.Errorf("no valid md5 hashes found in response")
	}
	return checksums, nil
}

func getWPPluginInfo(filePath string) (string, string, string) {
	// Must be inside wp-content/plugins/
	if !strings.Contains(filePath, filepath.Join("wp-content", "plugins")) {
		return "", "", ""
	}

	parts := strings.Split(filepath.ToSlash(filePath), "/")
	var pluginsIndex int = -1
	for i, part := range parts {
		if part == "plugins" {
			pluginsIndex = i
			break
		}
	}

	if pluginsIndex == -1 || pluginsIndex+1 >= len(parts) {
		return "", "", ""
	}

	pluginSlug := parts[pluginsIndex+1]
	pluginDir := filepath.Join(parts[:pluginsIndex+2]...)

	if runtime.GOOS == "windows" {
		pluginDir = strings.ReplaceAll(pluginDir, "/", "\\")
	} else {
		pluginDir = "/" + pluginDir
	}

	mainFileCandidates := []string{
		filepath.Join(pluginDir, pluginSlug+".php"),
		filepath.Join(pluginDir, "index.php"),
	}

	// Read version from main plugin file
	version := ""
	for _, cand := range mainFileCandidates {
		if b, err := os.ReadFile(cand); err == nil {
			m := pluginVersionRegex.FindStringSubmatch(string(b))
			if len(m) > 1 {
				version = m[1]
				break
			}
		}
	}

	// If specific main files didn't work, scan all .php files in the root of the plugin directory
	if version == "" {
		entries, err := os.ReadDir(pluginDir)
		if err == nil {
			for _, entry := range entries {
				if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".php") {
					b, err := os.ReadFile(filepath.Join(pluginDir, entry.Name()))
					if err == nil {
						m := pluginVersionRegex.FindStringSubmatch(string(b))
						if len(m) > 1 {
							version = m[1]
							break
						}
					}
				}
			}
		}
	}

	return pluginDir, pluginSlug, version
}

func checkWPPlugin(filePath string) (CheckResult, string) {
	ensureCacheLoaded()

	pluginDir, slug, version := getWPPluginInfo(filePath)
	if pluginDir == "" || slug == "" || version == "" {
		return ResultUnknown, ""
	}

	cacheKey := slug + ":" + version

	wpPluginChecksumsMu.RLock()
	checksums, ok := wpPluginChecksums[cacheKey]
	wpPluginChecksumsMu.RUnlock()

	if !ok {
		wpPluginChecksumsMu.Lock()
		checksums, ok = wpPluginChecksums[cacheKey]
		if !ok {
			// First, try to load from local premium baseline
			localChecksums, err := loadLocalBaseline(slug, version)
			if err == nil && len(localChecksums) > 0 {
				pterm.Info.Printf("\rUsing local baseline for %s (%s)...      \n", slug, version)
				wpPluginChecksums[cacheKey] = localChecksums
				checksums = localChecksums
			} else {
				pterm.Info.Printf("\rFetching WP Plugin %s (%s) checksums...      \n", slug, version)
				fetched, err := fetchWPPluginChecksums(slug, version)
				if err == nil {
					wpPluginChecksums[cacheKey] = fetched
					checksums = fetched
					cacheMu.Lock()
					saveCacheLocked()
					cacheMu.Unlock()
				} else {
					// Prevent re-fetching if failed
					wpPluginChecksums[cacheKey] = map[string]string{}
					checksums = wpPluginChecksums[cacheKey]
				}
			}
		}
		wpPluginChecksumsMu.Unlock()
	}

	if len(checksums) == 0 {
		return ResultUnknown, ""
	}

	relPath, err := filepath.Rel(pluginDir, filePath)
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
		return ResultMatch, "WP Plugin (" + slug + ")"
	}
	return ResultModified, "WP Plugin (" + slug + ")"
}

func CheckCoreFile(filePath string) (CheckResult, string) {
	// First check WordPress Core
	res, fw := checkWordPress(filePath)
	if res != ResultUnknown {
		return res, fw
	}

	// Then check WordPress Plugins
	res, fw = checkWPPlugin(filePath)
	if res != ResultUnknown {
		return res, fw
	}

	// Then check Laravel
	res, fw = checkLaravel(filePath)
	if res != ResultUnknown {
		return res, fw
	}

	// Then check CodeIgniter 4
	res, fw = checkCI4(filePath)
	if res != ResultUnknown {
		return res, fw
	}

	// Then check Yii2
	res, fw = checkYii2(filePath)
	if res != ResultUnknown {
		return res, fw
	}

	return ResultUnknown, ""
}

func checkWordPress(filePath string) (CheckResult, string) {
	ensureCacheLoaded()

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
				cacheMu.Lock()
				saveCacheLocked()
				cacheMu.Unlock()
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

func getFrameworkRoot(filePath, indicatorFile, framework string) string {
	dir := filepath.Dir(filePath)

	cacheKey := framework + ":" + dir
	frameworkRootsMu.RLock()
	cachedRoot, cached := frameworkRoots[cacheKey]
	frameworkRootsMu.RUnlock()

	if cached {
		return cachedRoot
	}

	currentDir := dir
	var root string

	for {
		if _, err := os.Stat(filepath.Join(currentDir, indicatorFile)); err == nil {
			root = currentDir
			break
		}
		parent := filepath.Dir(currentDir)
		if parent == currentDir {
			break
		}
		currentDir = parent
	}

	frameworkRootsMu.Lock()
	frameworkRoots[cacheKey] = root
	frameworkRootsMu.Unlock()

	return root
}

func checkVendorFile(filePath, root string) CheckResult {
	relPath, err := filepath.Rel(root, filePath)
	if err != nil {
		return ResultUnknown
	}
	relPath = filepath.ToSlash(relPath)

	if strings.HasPrefix(relPath, "vendor/") {
		return ResultMatch
	}
	return ResultUnknown
}

func checkLaravel(filePath string) (CheckResult, string) {
	root := getFrameworkRoot(filePath, "artisan", "laravel")
	if root == "" {
		return ResultUnknown, ""
	}

	if checkVendorFile(filePath, root) == ResultMatch {
		return ResultMatch, "Laravel Vendor"
	}
	return ResultUnknown, ""
}

func checkCI4(filePath string) (CheckResult, string) {
	root := getFrameworkRoot(filePath, "spark", "ci4")
	if root == "" {
		return ResultUnknown, ""
	}

	relPath, _ := filepath.Rel(root, filePath)
	relPath = filepath.ToSlash(relPath)

	if strings.HasPrefix(relPath, "vendor/") || strings.HasPrefix(relPath, "system/") {
		return ResultMatch, "CodeIgniter4 Core/Vendor"
	}
	return ResultUnknown, ""
}

func checkYii2(filePath string) (CheckResult, string) {
	root := getFrameworkRoot(filePath, "yii", "yii2")
	if root == "" {
		return ResultUnknown, ""
	}

	if checkVendorFile(filePath, root) == ResultMatch {
		return ResultMatch, "Yii2 Vendor"
	}
	return ResultUnknown, ""
}
