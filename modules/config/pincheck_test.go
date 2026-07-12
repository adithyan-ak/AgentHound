package config

import (
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/common"
)

func TestIsUnpinned(t *testing.T) {
	tests := []struct {
		name    string
		command string
		args    []string
		want    bool
	}{
		{
			name:    "npx -y with unpinned scoped package",
			command: "npx",
			args:    []string{"-y", "@modelcontextprotocol/server-postgres"},
			want:    true,
		},
		{
			name:    "npx -y with pinned scoped package",
			command: "npx",
			args:    []string{"-y", "@modelcontextprotocol/server-postgres@1.0.0"},
			want:    false,
		},
		{
			name:    "npx without -y is still unpinned",
			command: "npx",
			args:    []string{"@scope/pkg"},
			want:    true,
		},
		{
			name:    "npx with pinned unscoped package",
			command: "npx",
			args:    []string{"-y", "some-tool@2.0.0"},
			want:    false,
		},
		{
			name:    "npx with unpinned unscoped package",
			command: "npx",
			args:    []string{"-y", "some-tool"},
			want:    true,
		},
		{
			name:    "uvx unpinned",
			command: "uvx",
			args:    []string{"some-pkg"},
			want:    true,
		},
		{
			name:    "uvx pinned",
			command: "uvx",
			args:    []string{"some-pkg==1.0.0"},
			want:    false,
		},
		{
			name:    "uvx with flags unpinned",
			command: "uvx",
			args:    []string{"--quiet", "some-pkg"},
			want:    true,
		},
		{
			name:    "non-npx/uvx command",
			command: "node",
			args:    []string{"server.js"},
			want:    false,
		},
		{
			name:    "docker command",
			command: "docker",
			args:    []string{"run", "some-image"},
			want:    false,
		},
		{
			name:    "npx with --yes flag",
			command: "npx",
			args:    []string{"--yes", "some-tool"},
			want:    true,
		},
		{
			name:    "npx empty args",
			command: "npx",
			args:    []string{},
			want:    false,
		},
		{
			name:    "uvx empty args",
			command: "uvx",
			args:    []string{},
			want:    false,
		},
		{
			name:    "npx only flags",
			command: "npx",
			args:    []string{"-y"},
			want:    false,
		},
		{
			name:    "npx -y pinned scoped with extra flags",
			command: "npx",
			args:    []string{"-y", "@scope/pkg@3.2.1"},
			want:    false,
		},
		{
			name:    "uvx only flags no package",
			command: "uvx",
			args:    []string{"--verbose"},
			want:    false,
		},
		{
			name:    "path-qualified npx",
			command: "/usr/local/bin/npx",
			args:    []string{"-y", "some-tool"},
			want:    true,
		},
		{
			name:    "windows path-qualified uvx",
			command: `C:\Users\agent\.local\bin\uvx.exe`,
			args:    []string{"some-pkg==1.0.0"},
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsUnpinned(tt.command, tt.args)
			if got != tt.want {
				t.Errorf("IsUnpinned(%q, %v) = %v, want %v", tt.command, tt.args, got, tt.want)
			}
		})
	}
}

func TestAssessPinningPreservesUnknown(t *testing.T) {
	tests := []struct {
		command string
		args    []string
		want    common.PinningStatus
	}{
		{"npx", nil, common.PinningUnknown},
		{"npx", []string{"-y", "pkg"}, common.PinningUnpinned},
		{"npx", []string{"-y", "pkg@1.2.3"}, common.PinningPinned},
		{"uvx", []string{"--verbose"}, common.PinningUnknown},
		{"node", []string{"server.js"}, common.PinningUnknown},
		{"/opt/homebrew/bin/npx", []string{"pkg"}, common.PinningUnpinned},
		{`C:\tools\npx`, []string{"pkg@1.2.3"}, common.PinningPinned},
		{`C:\tools\uvx.exe`, []string{"pkg==1.2.3"}, common.PinningPinned},
		{"custom-launcher", []string{"pkg@1.2.3"}, common.PinningUnknown},
	}
	for _, tt := range tests {
		if got := AssessPinning(tt.command, tt.args); got != tt.want {
			t.Errorf("AssessPinning(%q, %v) = %q, want %q", tt.command, tt.args, got, tt.want)
		}
	}
}
