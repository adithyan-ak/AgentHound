package credreach

import (
	"context"
	"encoding/json"
	"time"
)

// AccessProof is the complete in-process differential resource-read result.
// Content is retained only from a successful credentialed read so the unified
// scan can preserve it on the resource node.
type AccessProof struct {
	Control    ProbeResult
	Credential ProbeResult
	Outcome    Outcome
	Content    json.RawMessage
}

// VerifyAccess performs the unauthenticated control and credentialed exact
// resource read in one invocation.
func VerifyAccess(
	ctx context.Context,
	endpoint, resourceURI, credential string,
	insecure bool,
	timeout time.Duration,
) AccessProof {
	prober := &mcpProber{}
	control, controlContent := prober.probeWithContent(ctx, ProbeRequest{
		Host: endpoint, ResourceURI: resourceURI, Insecure: insecure, Timeout: timeout,
	})
	credentialed, content := prober.probeWithContent(ctx, ProbeRequest{
		Host: endpoint, ResourceURI: resourceURI, Credential: credential,
		Insecure: insecure, Timeout: timeout,
	})
	content = credentialedContent(content)
	if len(content) == 0 {
		content = credentialedContent(controlContent)
	}
	return AccessProof{
		Control: control, Credential: credentialed,
		Outcome: Classify(control, credentialed), Content: content,
	}
}

func credentialedContent(content json.RawMessage) json.RawMessage {
	if len(content) == 0 || string(content) == "null" {
		return nil
	}
	return content
}
