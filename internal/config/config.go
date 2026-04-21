package config

const (
	Reset   = "\033[0m"
	Red     = "\033[31m"
	Green   = "\033[32m"
	Yellow  = "\033[33m"
	Blue    = "\033[34m"
	Magenta = "\033[35m"
	Cyan    = "\033[36m"
	White   = "\033[37m"
)

const DefaultMinScore = 4
const DefaultMaxEvidence = 5
const RootPermissionWarning = "not enough permission to do this, gotta root"

var SuspiciousExtensions = map[string]struct{}{
	".php":   {},
	".phtml": {},
	".php3":  {},
	".php4":  {},
	".php5":  {},
	".phar":  {},
	".inc":   {},
	".asp":   {},
	".aspx":  {},
	".ashx":  {},
	".jsp":   {},
	".jspx":  {},
	".cfm":   {},
	".cgi":   {},
	".pl":    {},
	".py":    {},
	".sh":    {},
	".js":    {},
	".ts":    {},
	".jsx":   {},
	".tsx":   {},
	".cjs":   {},
	".mjs":   {},
}

var IgnoredExtensions = map[string]struct{}{
	".jpg":         {},
	".jpeg":        {},
	".png":         {},
	".gif":         {},
	".svg":         {},
	".ico":         {},
	".webp":        {},
	".heic":        {},
	".avif":        {},
	".tiff":        {},
	".bimap":       {}, // or .bmp
	".bmp":         {},
	".jpg_backup":  {},
	".jpeg_backup": {},
	".zip":         {},
	".tar":         {},
	".gz":          {},
	".pdf":         {},
	".pptx":        {},
	".ppt":         {},
	".docx":        {},
	".xlsx":        {},
	".csv":         {},
	".xml":         {},
	".db":          {},
	".pem":         {},
	".css":         {},
	".txt":         {},
	".eot":         {},
	".woff":        {},
	".woff2":       {},
	".ttf":         {},
	".bcmap":       {},
	".mp3":         {},
	".mp4":         {},
}

var ExtCategory = map[string]string{
	".php":   "php",
	".phtml": "php",
	".php3":  "php",
	".php4":  "php",
	".php5":  "php",
	".phar":  "php",
	".inc":   "php",
	".js":    "js",
	".ts":    "js",
	".jsx":   "js",
	".tsx":   "js",
	".cjs":   "js",
	".mjs":   "js",
	".jsp":   "java",
	".jspx":  "java",
	".asp":   "asp",
	".aspx":  "asp",
	".ashx":  "asp",
	".py":    "python",
	".sh":    "shell",
	".bash":  "shell",
	".pl":    "perl",
	".cfm":   "cfm",
}

const Banner = `
` + Red + `
===========================================================================================
` + Cyan + `
 _    _            _     _ _____ _          _ _  ______ _           _           
| |  | |          | |   | /  ___| |        | | | |  ___(_)         | |          
| |  | | ___  _ __| | __| \ ` + "`" + `--.| |__   ___| | | | |_   _ _ __   __| | ___ _ __ 
| |/\| |/ _ \| '__| |/ _` + "`" + ` |` + "`" + `--. \ '_ \ / _ \ | | |  _| | | '_ \ / _` + "`" + ` |/ _ \ '__|
\  /\  / (_) | |  | | (_| /\__/ / | | |  __/ | | | |   | | | | | (_| |  __/ |   
 \/  \/ \___/|_|  |_|\__,_\____/|_| |_|\___|_|_| \_|   |_|_| |_|\__,_|\___|_|  
 ` + Reset + `
 made with love by ` + Yellow + ` Worldsavior/Aryma-f4 ` + Magenta + `^^	 ` + Green + `	v3.5.0 Stable Build  ` + Reset + `
===========================================================================================
`

const MenuText = `
Please choose an option:
1. Normal WebShell Detection
2. Remove String from Files
3. Deep Scan (files, traffic, rootkit)
`
