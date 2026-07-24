package cli

import (
	"os"
	"testing"
)

func TestResolveInstructionRecursion(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("no home dir: %v", err)
	}

	tests := []struct {
		name              string
		projectDir        string
		projectDirChanged bool
		deep              bool
		deepRoot          string
		wantRoot          string
		wantDeep          bool
	}{
		{name: "default host scan does not recurse"},
		{
			name:              "project-dir is a strict root",
			projectDir:        "/repo",
			projectDirChanged: true,
			wantRoot:          "/repo",
		},
		{
			name:     "deep defaults to home",
			deep:     true,
			wantRoot: home,
			wantDeep: true,
		},
		{
			name:     "deep-root overrides",
			deep:     true,
			deepRoot: "/srv/other",
			wantRoot: "/srv/other",
			wantDeep: true,
		},
		{
			name:              "deep wins over project-dir",
			projectDir:        "/repo",
			projectDirChanged: true,
			deep:              true,
			wantRoot:          home,
			wantDeep:          true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root, isDeep, err := resolveInstructionRecursion(tc.projectDir, tc.projectDirChanged, tc.deep, tc.deepRoot)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if root != tc.wantRoot || isDeep != tc.wantDeep {
				t.Fatalf("resolveInstructionRecursion = (%q, %v), want (%q, %v)", root, isDeep, tc.wantRoot, tc.wantDeep)
			}
		})
	}
}
