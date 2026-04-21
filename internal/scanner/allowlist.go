package scanner

import (
	"regexp"
)

var allowlistRules = []*regexp.Regexp{
	// Image optimizers that safely fallback to shell_exec
	regexp.MustCompile(`(?i)class\s+ExecWithFallback`),
	regexp.MustCompile(`(?i)namespace\s+.*\\ExecWithFallback`),
	// Sodium compat fallback
	regexp.MustCompile(`(?i)class\s+Compat\s+extends\s+ParagonIE_Sodium_Compat`),
	// Crypt libraries (phpseclib)
	regexp.MustCompile(`(?i)namespace\s+phpseclib\\Crypt`),
}

func isAllowlistedFile(buffer []byte) bool {
	content := string(buffer)
	for _, rule := range allowlistRules {
		if rule.MatchString(content) {
			return true
		}
	}
	return false
}
