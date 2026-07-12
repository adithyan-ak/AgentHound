package config

import (
	"path"
	"strings"

	"github.com/adithyan-ak/agenthound/sdk/common"
)

func IsUnpinned(command string, args []string) bool {
	return AssessPinning(command, args) == common.PinningUnpinned
}

func AssessPinning(command string, args []string) common.PinningStatus {
	switch executableBase(command) {
	case "npx":
		pkg := findPackageArg(args)
		if pkg == "" {
			return common.PinningUnknown
		}
		if hasVersionSuffix(pkg) {
			return common.PinningPinned
		}
		return common.PinningUnpinned
	case "uvx":
		if len(args) == 0 {
			return common.PinningUnknown
		}
		pkg := args[len(args)-1]
		if strings.HasPrefix(pkg, "-") {
			return common.PinningUnknown
		}
		if strings.Contains(pkg, "==") {
			return common.PinningPinned
		}
		return common.PinningUnpinned
	default:
		// A stdio launcher outside the package managers understood here has
		// not been assessed. It is not evidence that pinning is inapplicable.
		return common.PinningUnknown
	}
}

func executableBase(command string) string {
	// Configs may be generated on a different platform from the collector.
	// Normalize both slash styles before taking the basename.
	normalized := strings.ReplaceAll(strings.TrimSpace(command), `\`, "/")
	base := strings.ToLower(path.Base(normalized))
	for _, suffix := range []string{".exe", ".cmd", ".bat"} {
		base = strings.TrimSuffix(base, suffix)
	}
	return base
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
