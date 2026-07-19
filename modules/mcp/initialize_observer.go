package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

// tasksCapabilityState represents only claims that can be made from the raw
// initialize response. The v1.6.1 MCP SDK does not expose the standard tasks
// capability, so its typed InitializeResult cannot distinguish these states.
type tasksCapabilityState uint8

const (
	tasksCapabilityUnknown tasksCapabilityState = iota
	tasksCapabilityAbsent
	tasksCapabilityPresent
)

type initializeWireObserver struct {
	mu    sync.RWMutex
	seen  bool
	tasks tasksCapabilityState
}

func (o *initializeWireObserver) observeResult(result json.RawMessage) bool {
	state, ok := rawTasksCapability(result)
	if !ok {
		return false
	}
	o.mu.Lock()
	o.seen = true
	o.tasks = state
	o.mu.Unlock()
	return true
}

func (o *initializeWireObserver) tasksState() tasksCapabilityState {
	o.mu.RLock()
	defer o.mu.RUnlock()
	if !o.seen {
		return tasksCapabilityUnknown
	}
	return o.tasks
}

func rawTasksCapability(result json.RawMessage) (tasksCapabilityState, bool) {
	var initialize map[string]json.RawMessage
	if err := json.Unmarshal(result, &initialize); err != nil || initialize == nil {
		return tasksCapabilityUnknown, false
	}

	capabilitiesJSON, ok := initialize["capabilities"]
	if !ok || bytes.Equal(bytes.TrimSpace(capabilitiesJSON), []byte("null")) {
		return tasksCapabilityUnknown, true
	}
	var capabilities map[string]json.RawMessage
	if err := json.Unmarshal(capabilitiesJSON, &capabilities); err != nil || capabilities == nil {
		return tasksCapabilityUnknown, true
	}

	tasksJSON, ok := capabilities["tasks"]
	if !ok {
		return tasksCapabilityAbsent, true
	}
	tasksJSON = bytes.TrimSpace(tasksJSON)
	if len(tasksJSON) == 0 || tasksJSON[0] != '{' {
		return tasksCapabilityUnknown, true
	}
	var tasks map[string]json.RawMessage
	if err := json.Unmarshal(tasksJSON, &tasks); err != nil || tasks == nil {
		return tasksCapabilityUnknown, true
	}
	return tasksCapabilityPresent, true
}

// withInitializeWireObserver instruments the concrete transports built by this
// module without changing the streamable HTTP connection type. The SDK relies
// on a private method on that connection to install the negotiated protocol
// version, session ID behavior, and standalone SSE listener.
func withInitializeWireObserver(transport mcpsdk.Transport) (mcpsdk.Transport, *initializeWireObserver) {
	observer := &initializeWireObserver{}
	switch transport := transport.(type) {
	case *mcpsdk.StreamableClientTransport:
		clone := *transport
		clone.HTTPClient = observingHTTPClient(transport.HTTPClient, observer)
		return &clone, observer
	case *mcpsdk.CommandTransport, *mcpsdk.SSEClientTransport:
		return &initializeObservingTransport{base: transport, observer: observer}, observer
	default:
		return transport, observer
	}
}

func observingHTTPClient(client *http.Client, observer *initializeWireObserver) *http.Client {
	if client == nil {
		client = http.DefaultClient
	}
	clone := *client
	base := clone.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	clone.Transport = initializeObservingRoundTripper{base: base, observer: observer}
	return &clone
}

type initializeObservingRoundTripper struct {
	base     http.RoundTripper
	observer *initializeWireObserver
}

func (t initializeObservingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	initializeID, isInitialize := initializeRequestID(req)
	resp, err := t.base.RoundTrip(req)
	if err != nil || !isInitialize || resp.Body == nil {
		return resp, err
	}
	resp.Body = &initializeObservingBody{
		ReadCloser:   resp.Body,
		observer:     t.observer,
		initializeID: initializeID,
		contentType:  resp.Header.Get("Content-Type"),
	}
	return resp, nil
}

func initializeRequestID(req *http.Request) (string, bool) {
	if req.Method != http.MethodPost || req.GetBody == nil {
		return "", false
	}
	body, err := req.GetBody()
	if err != nil {
		return "", false
	}
	defer body.Close()
	raw, err := io.ReadAll(io.LimitReader(body, defaultObserverResponseBytes+1))
	if err != nil || int64(len(raw)) > defaultObserverResponseBytes {
		return "", false
	}
	var request struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
	}
	if err := json.Unmarshal(raw, &request); err != nil || request.Method != "initialize" {
		return "", false
	}
	return canonicalJSONRPCID(request.ID)
}

type initializeObservingBody struct {
	io.ReadCloser
	observer     *initializeWireObserver
	initializeID string
	contentType  string
	mu           sync.Mutex
	buffer       []byte
	resolved     bool
	overflowed   bool
}

func (b *initializeObservingBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if n > 0 {
		b.appendAndInspect(p[:n], false)
	}
	if err != nil {
		b.inspect(true)
	}
	return n, err
}

func (b *initializeObservingBody) Close() error {
	b.inspect(true)
	return b.ReadCloser.Close()
}

func (b *initializeObservingBody) appendAndInspect(data []byte, final bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.resolved || b.overflowed {
		return
	}
	remaining := int(defaultObserverResponseBytes) - len(b.buffer)
	if len(data) > remaining {
		b.overflowed = true
		b.buffer = nil
		return
	}
	b.buffer = append(b.buffer, data...)
	b.inspectLocked(final)
}

func (b *initializeObservingBody) inspect(final bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.inspectLocked(final)
}

func (b *initializeObservingBody) inspectLocked(final bool) {
	if b.resolved || b.overflowed {
		return
	}
	mediaType := strings.ToLower(strings.TrimSpace(strings.SplitN(b.contentType, ";", 2)[0]))
	switch mediaType {
	case "application/json":
		b.resolved = b.observeEnvelope(b.buffer)
	case "text/event-stream":
		for _, data := range completeSSEData(b.buffer, final) {
			if b.observeEnvelope(data) {
				b.resolved = true
				break
			}
		}
	}
}

func (b *initializeObservingBody) observeEnvelope(payload []byte) bool {
	var response struct {
		ID     json.RawMessage `json:"id"`
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(payload, &response); err != nil {
		return false
	}
	responseID, ok := canonicalJSONRPCID(response.ID)
	if !ok || responseID != b.initializeID || len(response.Result) == 0 {
		return false
	}
	return b.observer.observeResult(response.Result)
}

func completeSSEData(raw []byte, final bool) [][]byte {
	normalized := bytes.ReplaceAll(raw, []byte("\r\n"), []byte("\n"))
	normalized = bytes.ReplaceAll(normalized, []byte("\r"), []byte("\n"))
	events := bytes.Split(normalized, []byte("\n\n"))
	if !final && !bytes.HasSuffix(normalized, []byte("\n\n")) {
		events = events[:len(events)-1]
	}

	var result [][]byte
	for _, event := range events {
		var dataLines [][]byte
		eventName := ""
		for _, line := range bytes.Split(event, []byte("\n")) {
			if bytes.HasPrefix(line, []byte("event:")) {
				eventName = strings.TrimSpace(string(line[len("event:"):]))
				continue
			}
			if !bytes.HasPrefix(line, []byte("data:")) {
				continue
			}
			data := line[len("data:"):]
			if len(data) > 0 && data[0] == ' ' {
				data = data[1:]
			}
			dataLines = append(dataLines, data)
		}
		if len(dataLines) > 0 && (eventName == "" || eventName == "message") {
			result = append(result, bytes.Join(dataLines, []byte("\n")))
		}
	}
	return result
}

type initializeObservingTransport struct {
	base     mcpsdk.Transport
	observer *initializeWireObserver
}

func (t *initializeObservingTransport) Connect(ctx context.Context) (mcpsdk.Connection, error) {
	connection, err := t.base.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &initializeObservingConnection{Connection: connection, observer: t.observer}, nil
}

type initializeObservingConnection struct {
	mcpsdk.Connection
	observer *initializeWireObserver

	mu           sync.RWMutex
	initializeID string
}

func (c *initializeObservingConnection) Write(ctx context.Context, message jsonrpc.Message) error {
	if request, ok := message.(*jsonrpc.Request); ok && request.Method == "initialize" {
		if requestID, ok := canonicalSDKID(request.ID); ok {
			c.mu.Lock()
			c.initializeID = requestID
			c.mu.Unlock()
		}
	}
	return c.Connection.Write(ctx, message)
}

func (c *initializeObservingConnection) Read(ctx context.Context) (jsonrpc.Message, error) {
	message, err := c.Connection.Read(ctx)
	if err != nil {
		return message, err
	}
	response, ok := message.(*jsonrpc.Response)
	if !ok || len(response.Result) == 0 {
		return message, nil
	}
	responseID, ok := canonicalSDKID(response.ID)
	if !ok {
		return message, nil
	}
	c.mu.RLock()
	initializeID := c.initializeID
	c.mu.RUnlock()
	if initializeID != "" && responseID == initializeID {
		c.observer.observeResult(response.Result)
	}
	return message, nil
}

func canonicalSDKID(id jsonrpc.ID) (string, bool) {
	raw, err := json.Marshal(id.Raw())
	if err != nil {
		return "", false
	}
	return canonicalJSONRPCID(raw)
}

func canonicalJSONRPCID(raw json.RawMessage) (string, bool) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return "", false
	}
	var value any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return "", false
	}
	switch value := value.(type) {
	case string:
		encoded, err := json.Marshal(value)
		return string(encoded), err == nil
	case json.Number:
		return value.String(), true
	default:
		return "", false
	}
}

func applyInitializeWireObservation(node *ingest.Node, observer *initializeWireObserver) {
	if node == nil || observer == nil {
		return
	}
	switch observer.tasksState() {
	case tasksCapabilityPresent:
		node.Properties["has_tasks_capability"] = true
		capabilities, _ := node.Properties["capabilities"].([]string)
		for _, capability := range capabilities {
			if capability == "tasks" {
				return
			}
		}
		node.Properties["capabilities"] = append(capabilities, "tasks")
	case tasksCapabilityAbsent:
		node.Properties["has_tasks_capability"] = false
	case tasksCapabilityUnknown:
	}
}
