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

const (
	initializeMethod        = "initialize"
	discoverMethod          = "server/discover"
	discoverProtocolVersion = "2026-07-28"
)

// tasksCapabilityState represents only claims that can be made from a raw MCP
// handshake response. The SDK does not expose the standard tasks capability in
// its typed result, so AgentHound observes both legacy initialize and modern
// server/discover responses without altering their transport behavior.
type tasksCapabilityState uint8

const (
	tasksCapabilityUnknown tasksCapabilityState = iota
	tasksCapabilityAbsent
	tasksCapabilityPresent
)

type capabilityWireObserver struct {
	mu     sync.RWMutex
	seen   bool
	tasks  tasksCapabilityState
	method string
}

func (o *capabilityWireObserver) observeResult(method string, result json.RawMessage) bool {
	state, ok := rawTasksCapability(result)
	if !ok {
		return false
	}
	o.mu.Lock()
	o.seen = true
	o.tasks = state
	o.method = method
	o.mu.Unlock()
	return true
}

func (o *capabilityWireObserver) tasksState() tasksCapabilityState {
	o.mu.RLock()
	defer o.mu.RUnlock()
	if !o.seen {
		return tasksCapabilityUnknown
	}
	return o.tasks
}

func (o *capabilityWireObserver) handshakeMethod(protocolVersion string) string {
	o.mu.RLock()
	defer o.mu.RUnlock()
	if o.method != "" {
		return o.method
	}
	if protocolVersion >= discoverProtocolVersion {
		return discoverMethod
	}
	return initializeMethod
}

func isCapabilityHandshakeMethod(method string) bool {
	return method == initializeMethod || method == discoverMethod
}

func rawTasksCapability(result json.RawMessage) (tasksCapabilityState, bool) {
	var handshake map[string]json.RawMessage
	if err := json.Unmarshal(result, &handshake); err != nil || handshake == nil {
		return tasksCapabilityUnknown, false
	}

	capabilitiesJSON, ok := handshake["capabilities"]
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

// withCapabilityWireObserver instruments the concrete transports built by this
// module without changing the streamable HTTP connection type. The SDK relies
// on a private method on that connection to install the negotiated protocol
// version, session ID behavior, and standalone SSE listener.
func withCapabilityWireObserver(transport mcpsdk.Transport) (mcpsdk.Transport, *capabilityWireObserver) {
	observer := &capabilityWireObserver{}
	switch transport := transport.(type) {
	case *mcpsdk.StreamableClientTransport:
		clone := *transport
		clone.HTTPClient = observingHTTPClient(transport.HTTPClient, observer)
		return &clone, observer
	case *mcpsdk.CommandTransport, *mcpsdk.SSEClientTransport:
		return &capabilityObservingTransport{base: transport, observer: observer}, observer
	default:
		return transport, observer
	}
}

func observingHTTPClient(client *http.Client, observer *capabilityWireObserver) *http.Client {
	if client == nil {
		client = http.DefaultClient
	}
	clone := *client
	base := clone.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	clone.Transport = capabilityObservingRoundTripper{base: base, observer: observer}
	return &clone
}

type capabilityObservingRoundTripper struct {
	base     http.RoundTripper
	observer *capabilityWireObserver
}

func (t capabilityObservingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	requestID, method, isHandshake := capabilityRequest(req)
	resp, err := t.base.RoundTrip(req)
	if err != nil || !isHandshake || resp.Body == nil {
		return resp, err
	}
	resp.Body = &capabilityObservingBody{
		ReadCloser:  resp.Body,
		observer:    t.observer,
		requestID:   requestID,
		method:      method,
		contentType: resp.Header.Get("Content-Type"),
	}
	return resp, nil
}

func capabilityRequest(req *http.Request) (requestID, method string, ok bool) {
	if req.Method != http.MethodPost || req.GetBody == nil {
		return "", "", false
	}
	body, err := req.GetBody()
	if err != nil {
		return "", "", false
	}
	defer body.Close()
	raw, err := io.ReadAll(io.LimitReader(body, defaultObserverResponseBytes+1))
	if err != nil || int64(len(raw)) > defaultObserverResponseBytes {
		return "", "", false
	}
	var request struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
	}
	if err := json.Unmarshal(raw, &request); err != nil || !isCapabilityHandshakeMethod(request.Method) {
		return "", "", false
	}
	requestID, ok = canonicalJSONRPCID(request.ID)
	return requestID, request.Method, ok
}

type capabilityObservingBody struct {
	io.ReadCloser
	observer    *capabilityWireObserver
	requestID   string
	method      string
	contentType string
	mu          sync.Mutex
	buffer      []byte
	resolved    bool
	overflowed  bool
}

func (b *capabilityObservingBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if n > 0 {
		b.appendAndInspect(p[:n], false)
	}
	if err != nil {
		b.inspect(true)
	}
	return n, err
}

func (b *capabilityObservingBody) Close() error {
	b.inspect(true)
	return b.ReadCloser.Close()
}

func (b *capabilityObservingBody) appendAndInspect(data []byte, final bool) {
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

func (b *capabilityObservingBody) inspect(final bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.inspectLocked(final)
}

func (b *capabilityObservingBody) inspectLocked(final bool) {
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

func (b *capabilityObservingBody) observeEnvelope(payload []byte) bool {
	var response struct {
		ID     json.RawMessage `json:"id"`
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(payload, &response); err != nil {
		return false
	}
	responseID, ok := canonicalJSONRPCID(response.ID)
	if !ok || responseID != b.requestID || len(response.Result) == 0 {
		return false
	}
	return b.observer.observeResult(b.method, response.Result)
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

type capabilityObservingTransport struct {
	base     mcpsdk.Transport
	observer *capabilityWireObserver
}

func (t *capabilityObservingTransport) Connect(ctx context.Context) (mcpsdk.Connection, error) {
	connection, err := t.base.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &capabilityObservingConnection{Connection: connection, observer: t.observer}, nil
}

type capabilityObservingConnection struct {
	mcpsdk.Connection
	observer *capabilityWireObserver

	mu       sync.Mutex
	requests map[string]string
}

func (c *capabilityObservingConnection) Write(ctx context.Context, message jsonrpc.Message) error {
	request, isRequest := message.(*jsonrpc.Request)
	if !isRequest || !isCapabilityHandshakeMethod(request.Method) {
		return c.Connection.Write(ctx, message)
	}
	requestID, ok := canonicalSDKID(request.ID)
	if !ok {
		return c.Connection.Write(ctx, message)
	}
	c.mu.Lock()
	if c.requests == nil {
		c.requests = make(map[string]string)
	}
	c.requests[requestID] = request.Method
	c.mu.Unlock()
	if err := c.Connection.Write(ctx, message); err != nil {
		c.mu.Lock()
		delete(c.requests, requestID)
		c.mu.Unlock()
		return err
	}
	return nil
}

func (c *capabilityObservingConnection) Read(ctx context.Context) (jsonrpc.Message, error) {
	message, err := c.Connection.Read(ctx)
	if err != nil {
		return message, err
	}
	response, ok := message.(*jsonrpc.Response)
	if !ok {
		return message, nil
	}
	responseID, ok := canonicalSDKID(response.ID)
	if !ok {
		return message, nil
	}
	c.mu.Lock()
	method := c.requests[responseID]
	delete(c.requests, responseID)
	c.mu.Unlock()
	if method != "" && len(response.Result) > 0 {
		c.observer.observeResult(method, response.Result)
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

func applyCapabilityWireObservation(node *ingest.Node, observer *capabilityWireObserver) {
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
