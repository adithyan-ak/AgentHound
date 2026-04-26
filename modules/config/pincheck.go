package config

import "strings"

func IsUnpinned(command string, args []string) bool {
	switch command {
	case "npx":
		return isNpxUnpinned(args)
	case "uvx":
		return isUvxUnpinned(args)
	default:
		return false
	}
}

func isNpxUnpinned(args []string) bool {
	pkg := findPackageArg(args)
	if pkg == "" {
		return false
	}
	return !hasVersionSuffix(pkg)
}

func isUvxUnpinned(args []string) bool {
	if len(args) == 0 {
		return false
	}
	pkg := args[len(args)-1]
	if strings.HasPrefix(pkg, "-") {
		return false
	}
	return !strings.Contains(pkg, "==")
}

func findPackageArg(args []string) string {
	for i, arg := range args {
		if arg == "-y" || arg == "--yes" {
			continue
		}
		if arg == "-p" || arg == "--package" {
			if i+1 < len(args) {
				return args[i+1]
			}
			return ""
		}
		if strings.HasPrefix(arg, "-") {
			continue
		}
		return arg
	}
	return ""
}

func hasVersionSuffix(pkg string) bool {
	// Scoped packages: @scope/name@version
	if strings.HasPrefix(pkg, "@") {
		afterScope := strings.Index(pkg[1:], "/")
		if afterScope == -1 {
			return false
		}
		nameAndVersion := pkg[afterScope+2:]
		return strings.Contains(nameAndVersion, "@")
	}
	// Unscoped packages: name@version
	return strings.Contains(pkg, "@")
}
