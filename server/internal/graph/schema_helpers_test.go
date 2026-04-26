package graph

import (
	"errors"
	"strings"
	"testing"
)

func TestConstraintCypher(t *testing.T) {
	t.Run("ForRequire syntax", func(t *testing.T) {
		cypher := constraintCypher("MCPServer", true)

		if !strings.Contains(cypher, "FOR (n:MCPServer)") {
			t.Errorf("expected FOR clause with label, got %q", cypher)
		}
		if !strings.Contains(cypher, "REQUIRE n.objectid IS UNIQUE") {
			t.Errorf("expected REQUIRE clause, got %q", cypher)
		}
		if !strings.Contains(cypher, "IF NOT EXISTS") {
			t.Errorf("expected IF NOT EXISTS, got %q", cypher)
		}
		if !strings.Contains(cypher, "unique_mcpserver_objectid") {
			t.Errorf("expected lowercase constraint name, got %q", cypher)
		}
	})

	t.Run("OnAssert syntax", func(t *testing.T) {
		cypher := constraintCypher("MCPTool", false)

		if !strings.Contains(cypher, "ON (n:MCPTool)") {
			t.Errorf("expected ON clause with label, got %q", cypher)
		}
		if !strings.Contains(cypher, "ASSERT n.objectid IS UNIQUE") {
			t.Errorf("expected ASSERT clause, got %q", cypher)
		}
		if strings.Contains(cypher, "IF NOT EXISTS") {
			t.Errorf("ON/ASSERT syntax should not contain IF NOT EXISTS, got %q", cypher)
		}
		if !strings.Contains(cypher, "unique_mcptool_objectid") {
			t.Errorf("expected lowercase constraint name, got %q", cypher)
		}
	})

	t.Run("constraint name is lowercase label", func(t *testing.T) {
		cypher := constraintCypher("A2AAgent", true)
		if !strings.Contains(cypher, "unique_a2aagent_objectid") {
			t.Errorf("expected 'unique_a2aagent_objectid', got %q", cypher)
		}
	})
}

func TestIndexCypher(t *testing.T) {
	t.Run("ForRequire syntax", func(t *testing.T) {
		cypher := indexCypher("MCPServer", "name", true)

		if !strings.Contains(cypher, "IF NOT EXISTS") {
			t.Errorf("expected IF NOT EXISTS, got %q", cypher)
		}
		if !strings.Contains(cypher, "FOR (n:MCPServer)") {
			t.Errorf("expected FOR clause with label, got %q", cypher)
		}
		if !strings.Contains(cypher, "ON (n.name)") {
			t.Errorf("expected ON property clause, got %q", cypher)
		}
		if !strings.Contains(cypher, "idx_mcpserver_name") {
			t.Errorf("expected index name, got %q", cypher)
		}
	})

	t.Run("OnAssert syntax uses same format", func(t *testing.T) {
		cypher := indexCypher("MCPTool", "description_hash", false)

		if !strings.Contains(cypher, "FOR (n:MCPTool)") {
			t.Errorf("expected FOR clause, got %q", cypher)
		}
		if !strings.Contains(cypher, "ON (n.description_hash)") {
			t.Errorf("expected ON property clause, got %q", cypher)
		}
		if !strings.Contains(cypher, "idx_mcptool_description_hash") {
			t.Errorf("expected index name, got %q", cypher)
		}
	})

	t.Run("index name is lowercase label and property", func(t *testing.T) {
		cypher := indexCypher("A2AAgent", "url", true)
		if !strings.Contains(cypher, "idx_a2aagent_url") {
			t.Errorf("expected 'idx_a2aagent_url', got %q", cypher)
		}
	})
}

func TestIsConstraintExistsError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "nil error returns false",
			err:  nil,
			want: false,
		},
		{
			name: "generic already exists",
			err:  errors.New("constraint already exists"),
			want: true,
		},
		{
			name: "neo4j EquivalentSchemaRuleAlreadyExists",
			err:  errors.New("Neo.ClientError.Schema.EquivalentSchemaRuleAlreadyExists"),
			want: true,
		},
		{
			name: "equivalent constraint message",
			err:  errors.New("An equivalent constraint already exists"),
			want: true,
		},
		{
			name: "lowercase equivalent constraint",
			err:  errors.New("equivalent constraint already exists, label=MCPServer"),
			want: true,
		},
		{
			name: "unrelated error returns false",
			err:  errors.New("connection refused"),
			want: false,
		},
		{
			name: "empty error message returns false",
			err:  errors.New(""),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isConstraintExistsError(tt.err)
			if got != tt.want {
				t.Errorf("isConstraintExistsError(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}
