package scanner

type RuntimeOptions struct {
	DisableIntegrity bool
	ExcludePathParts []string
	ExcludeGlobs     []string
	IncludeExt       []string
	ExcludeExt       []string
	Paranoid         bool
	Verbose          bool
	NumWorkers       int
}
