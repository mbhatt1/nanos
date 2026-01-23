/*
 * Authority Kernel Proxy Daemon
 *
 * Provides network, LLM, and filesystem services to agents running in Nanos
 * via virtio-serial channel. This daemon runs on the host and handles
 * requests that the unikernel cannot perform directly.
 *
 * Protocol: Newline-delimited JSON over virtio-serial
 *
 * Request format:
 *   {"id":"uuid","op":"http_get","url":"https://...","headers":{...}}
 *
 * Response format:
 *   {"id":"uuid","ok":true,"data":{...}}
 *   {"id":"uuid","ok":false,"error":"message","code":-1}
 */

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Request from kernel
type Request struct {
	ID        string            `json:"id"`
	Op        string            `json:"op"`
	URL       string            `json:"url,omitempty"`
	Method    string            `json:"method,omitempty"`
	Headers   map[string]string `json:"headers,omitempty"`
	Body      string            `json:"body,omitempty"`
	Path      string            `json:"path,omitempty"`
	Data      string            `json:"data,omitempty"`
	Model     string            `json:"model,omitempty"`
	Prompt    string            `json:"prompt,omitempty"`
	Messages  []Message         `json:"messages,omitempty"`
	MaxTokens int               `json:"max_tokens,omitempty"`
	// TCP fields
	Host   string `json:"host,omitempty"`
	Port   int    `json:"port,omitempty"`
	ConnID uint64 `json:"conn_id,omitempty"`
	Size   int    `json:"size,omitempty"` // For recv buffer size
}

// Message for chat completions
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// Response to kernel
type Response struct {
	ID    string      `json:"id"`
	OK    bool        `json:"ok"`
	Data  interface{} `json:"data,omitempty"`
	Error string      `json:"error,omitempty"`
	Code  int         `json:"code,omitempty"`
}

// HTTPResponse for http operations
type HTTPResponse struct {
	Status     int               `json:"status"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body"`
	BodyBase64 string            `json:"body_base64,omitempty"`
}

// FileInfo for fs operations
type FileInfo struct {
	Name    string `json:"name"`
	Size    int64  `json:"size"`
	Mode    string `json:"mode"`
	IsDir   bool   `json:"is_dir"`
	ModTime int64  `json:"mod_time"`
}

// LLMResponse for inference operations
type LLMResponse struct {
	Content      string `json:"content"`
	Model        string `json:"model"`
	FinishReason string `json:"finish_reason"`
	Usage        struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		TotalTokens      int `json:"total_tokens"`
	} `json:"usage"`
}

// TCPConnection for tcp_connect response
type TCPConnection struct {
	ConnID     uint64 `json:"conn_id"`
	LocalAddr  string `json:"local_addr"`
	RemoteAddr string `json:"remote_addr"`
}

// TCPRecvResponse for tcp_recv response
type TCPRecvResponse struct {
	Data   string `json:"data"`   // Base64 encoded
	Length int    `json:"length"` // Actual bytes received
}

// Proxy handles all operations
type Proxy struct {
	httpClient  *http.Client
	allowedDirs []string
	llmEndpoint string
	llmAPIKey   string
	llmProvider string // "openai", "anthropic", "ollama"
	mu          sync.Mutex
	// TCP connection management
	tcpConns   map[uint64]net.Conn
	tcpMu      sync.RWMutex
	nextConnID uint64
}

func NewProxy(config *Config) *Proxy {
	return &Proxy{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		allowedDirs: config.AllowedDirs,
		llmEndpoint: config.LLMEndpoint,
		llmAPIKey:   config.LLMAPIKey,
		llmProvider: config.LLMProvider,
		tcpConns:    make(map[uint64]net.Conn),
		nextConnID:  1,
	}
}

// Config for proxy
type Config struct {
	AllowedDirs []string
	LLMEndpoint string
	LLMAPIKey   string
	LLMProvider string
}

func (p *Proxy) Handle(req *Request) *Response {
	switch req.Op {
	case "http_get":
		return p.handleHTTPGet(req)
	case "http_post":
		return p.handleHTTPPost(req)
	case "http_request":
		return p.handleHTTPRequest(req)
	case "fs_read":
		return p.handleFSRead(req)
	case "fs_write":
		return p.handleFSWrite(req)
	case "fs_stat":
		return p.handleFSStat(req)
	case "fs_list":
		return p.handleFSList(req)
	case "llm_complete":
		return p.handleLLMComplete(req)
	case "llm_chat":
		return p.handleLLMChat(req)
	case "tcp_connect":
		return p.handleTCPConnect(req)
	case "tcp_send":
		return p.handleTCPSend(req)
	case "tcp_recv":
		return p.handleTCPRecv(req)
	case "tcp_close":
		return p.handleTCPClose(req)
	case "ping":
		return &Response{ID: req.ID, OK: true, Data: map[string]string{"pong": "ok"}}
	default:
		return &Response{ID: req.ID, OK: false, Error: fmt.Sprintf("unknown op: %s", req.Op), Code: -1}
	}
}

// HTTP Operations

func (p *Proxy) handleHTTPGet(req *Request) *Response {
	httpReq, err := http.NewRequest("GET", req.URL, nil)
	if err != nil {
		return &Response{ID: req.ID, OK: false, Error: err.Error(), Code: -2}
	}

	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}

	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return &Response{ID: req.ID, OK: false, Error: err.Error(), Code: -3}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024)) // 10MB limit
	if err != nil {
		return &Response{ID: req.ID, OK: false, Error: err.Error(), Code: -4}
	}

	headers := make(map[string]string)
	for k := range resp.Header {
		headers[k] = resp.Header.Get(k)
	}

	return &Response{
		ID: req.ID,
		OK: true,
		Data: HTTPResponse{
			Status:  resp.StatusCode,
			Headers: headers,
			Body:    string(body),
		},
	}
}

func (p *Proxy) handleHTTPPost(req *Request) *Response {
	httpReq, err := http.NewRequest("POST", req.URL, strings.NewReader(req.Body))
	if err != nil {
		return &Response{ID: req.ID, OK: false, Error: err.Error(), Code: -2}
	}

	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}

	if httpReq.Header.Get("Content-Type") == "" {
		httpReq.Header.Set("Content-Type", "application/json")
	}

	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return &Response{ID: req.ID, OK: false, Error: err.Error(), Code: -3}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return &Response{ID: req.ID, OK: false, Error: err.Error(), Code: -4}
	}

	headers := make(map[string]string)
	for k := range resp.Header {
		headers[k] = resp.Header.Get(k)
	}

	return &Response{
		ID: req.ID,
		OK: true,
		Data: HTTPResponse{
			Status:  resp.StatusCode,
			Headers: headers,
			Body:    string(body),
		},
	}
}

func (p *Proxy) handleHTTPRequest(req *Request) *Response {
	method := req.Method
	if method == "" {
		method = "GET"
	}

	var bodyReader io.Reader
	if req.Body != "" {
		bodyReader = strings.NewReader(req.Body)
	}

	httpReq, err := http.NewRequest(method, req.URL, bodyReader)
	if err != nil {
		return &Response{ID: req.ID, OK: false, Error: err.Error(), Code: -2}
	}

	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}

	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return &Response{ID: req.ID, OK: false, Error: err.Error(), Code: -3}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return &Response{ID: req.ID, OK: false, Error: err.Error(), Code: -4}
	}

	headers := make(map[string]string)
	for k := range resp.Header {
		headers[k] = resp.Header.Get(k)
	}

	return &Response{
		ID: req.ID,
		OK: true,
		Data: HTTPResponse{
			Status:  resp.StatusCode,
			Headers: headers,
			Body:    string(body),
		},
	}
}

// Filesystem Operations

func (p *Proxy) isPathAllowed(path string) bool {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return false
	}

	// Resolve symlinks
	realPath, err := filepath.EvalSymlinks(absPath)
	if err != nil {
		// Path might not exist yet (for writes)
		realPath = absPath
	}

	for _, dir := range p.allowedDirs {
		allowedAbs, err := filepath.Abs(dir)
		if err != nil {
			continue
		}
		if strings.HasPrefix(realPath, allowedAbs) {
			return true
		}
	}
	return false
}

func (p *Proxy) handleFSRead(req *Request) *Response {
	if !p.isPathAllowed(req.Path) {
		return &Response{ID: req.ID, OK: false, Error: "path not allowed", Code: -13}
	}

	data, err := os.ReadFile(req.Path)
	if err != nil {
		return &Response{ID: req.ID, OK: false, Error: err.Error(), Code: -2}
	}

	return &Response{
		ID:   req.ID,
		OK:   true,
		Data: map[string]string{"content": string(data)},
	}
}

func (p *Proxy) handleFSWrite(req *Request) *Response {
	if !p.isPathAllowed(req.Path) {
		return &Response{ID: req.ID, OK: false, Error: "path not allowed", Code: -13}
	}

	// Ensure parent directory exists
	dir := filepath.Dir(req.Path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return &Response{ID: req.ID, OK: false, Error: err.Error(), Code: -2}
	}

	if err := os.WriteFile(req.Path, []byte(req.Data), 0644); err != nil {
		return &Response{ID: req.ID, OK: false, Error: err.Error(), Code: -3}
	}

	return &Response{
		ID:   req.ID,
		OK:   true,
		Data: map[string]int{"bytes_written": len(req.Data)},
	}
}

func (p *Proxy) handleFSStat(req *Request) *Response {
	if !p.isPathAllowed(req.Path) {
		return &Response{ID: req.ID, OK: false, Error: "path not allowed", Code: -13}
	}

	info, err := os.Stat(req.Path)
	if err != nil {
		return &Response{ID: req.ID, OK: false, Error: err.Error(), Code: -2}
	}

	return &Response{
		ID: req.ID,
		OK: true,
		Data: FileInfo{
			Name:    info.Name(),
			Size:    info.Size(),
			Mode:    info.Mode().String(),
			IsDir:   info.IsDir(),
			ModTime: info.ModTime().UnixMilli(),
		},
	}
}

func (p *Proxy) handleFSList(req *Request) *Response {
	if !p.isPathAllowed(req.Path) {
		return &Response{ID: req.ID, OK: false, Error: "path not allowed", Code: -13}
	}

	entries, err := os.ReadDir(req.Path)
	if err != nil {
		return &Response{ID: req.ID, OK: false, Error: err.Error(), Code: -2}
	}

	files := make([]FileInfo, 0, len(entries))
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}
		files = append(files, FileInfo{
			Name:    info.Name(),
			Size:    info.Size(),
			Mode:    info.Mode().String(),
			IsDir:   info.IsDir(),
			ModTime: info.ModTime().UnixMilli(),
		})
	}

	return &Response{
		ID:   req.ID,
		OK:   true,
		Data: map[string]interface{}{"entries": files},
	}
}

// LLM Operations

func (p *Proxy) handleLLMComplete(req *Request) *Response {
	if p.llmEndpoint == "" {
		return &Response{ID: req.ID, OK: false, Error: "LLM not configured", Code: -100}
	}

	switch p.llmProvider {
	case "openai":
		return p.openaiComplete(req)
	case "anthropic":
		return p.anthropicComplete(req)
	case "ollama":
		return p.ollamaComplete(req)
	default:
		return &Response{ID: req.ID, OK: false, Error: "unknown LLM provider", Code: -101}
	}
}

func (p *Proxy) handleLLMChat(req *Request) *Response {
	if p.llmEndpoint == "" {
		return &Response{ID: req.ID, OK: false, Error: "LLM not configured", Code: -100}
	}

	switch p.llmProvider {
	case "openai":
		return p.openaiChat(req)
	case "anthropic":
		return p.anthropicChat(req)
	case "ollama":
		return p.ollamaChat(req)
	default:
		return &Response{ID: req.ID, OK: false, Error: "unknown LLM provider", Code: -101}
	}
}

// OpenAI provider
func (p *Proxy) openaiComplete(req *Request) *Response {
	model := req.Model
	if model == "" {
		model = "gpt-4"
	}

	payload := map[string]interface{}{
		"model":      model,
		"messages":   []map[string]string{{"role": "user", "content": req.Prompt}},
		"max_tokens": req.MaxTokens,
	}
	if req.MaxTokens == 0 {
		payload["max_tokens"] = 1000
	}

	body, _ := json.Marshal(payload)

	httpReq, _ := http.NewRequest("POST", p.llmEndpoint+"/v1/chat/completions", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+p.llmAPIKey)

	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return &Response{ID: req.ID, OK: false, Error: err.Error(), Code: -3}
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		return &Response{ID: req.ID, OK: false, Error: string(respBody), Code: resp.StatusCode}
	}

	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
		Usage struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
			TotalTokens      int `json:"total_tokens"`
		} `json:"usage"`
		Model string `json:"model"`
	}

	if err := json.Unmarshal(respBody, &result); err != nil {
		return &Response{ID: req.ID, OK: false, Error: err.Error(), Code: -4}
	}

	content := ""
	finishReason := ""
	if len(result.Choices) > 0 {
		content = result.Choices[0].Message.Content
		finishReason = result.Choices[0].FinishReason
	}

	return &Response{
		ID: req.ID,
		OK: true,
		Data: LLMResponse{
			Content:      content,
			Model:        result.Model,
			FinishReason: finishReason,
			Usage: struct {
				PromptTokens     int `json:"prompt_tokens"`
				CompletionTokens int `json:"completion_tokens"`
				TotalTokens      int `json:"total_tokens"`
			}{
				PromptTokens:     result.Usage.PromptTokens,
				CompletionTokens: result.Usage.CompletionTokens,
				TotalTokens:      result.Usage.TotalTokens,
			},
		},
	}
}

func (p *Proxy) openaiChat(req *Request) *Response {
	model := req.Model
	if model == "" {
		model = "gpt-4"
	}

	messages := make([]map[string]string, len(req.Messages))
	for i, m := range req.Messages {
		messages[i] = map[string]string{"role": m.Role, "content": m.Content}
	}

	payload := map[string]interface{}{
		"model":      model,
		"messages":   messages,
		"max_tokens": req.MaxTokens,
	}
	if req.MaxTokens == 0 {
		payload["max_tokens"] = 1000
	}

	body, _ := json.Marshal(payload)

	httpReq, _ := http.NewRequest("POST", p.llmEndpoint+"/v1/chat/completions", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+p.llmAPIKey)

	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return &Response{ID: req.ID, OK: false, Error: err.Error(), Code: -3}
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		return &Response{ID: req.ID, OK: false, Error: string(respBody), Code: resp.StatusCode}
	}

	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
		Usage struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
			TotalTokens      int `json:"total_tokens"`
		} `json:"usage"`
		Model string `json:"model"`
	}

	if err := json.Unmarshal(respBody, &result); err != nil {
		return &Response{ID: req.ID, OK: false, Error: err.Error(), Code: -4}
	}

	content := ""
	finishReason := ""
	if len(result.Choices) > 0 {
		content = result.Choices[0].Message.Content
		finishReason = result.Choices[0].FinishReason
	}

	return &Response{
		ID: req.ID,
		OK: true,
		Data: LLMResponse{
			Content:      content,
			Model:        result.Model,
			FinishReason: finishReason,
			Usage: struct {
				PromptTokens     int `json:"prompt_tokens"`
				CompletionTokens int `json:"completion_tokens"`
				TotalTokens      int `json:"total_tokens"`
			}{
				PromptTokens:     result.Usage.PromptTokens,
				CompletionTokens: result.Usage.CompletionTokens,
				TotalTokens:      result.Usage.TotalTokens,
			},
		},
	}
}

// Anthropic provider
func (p *Proxy) anthropicComplete(req *Request) *Response {
	model := req.Model
	if model == "" {
		model = "claude-sonnet-4-20250514"
	}

	maxTokens := req.MaxTokens
	if maxTokens == 0 {
		maxTokens = 1000
	}

	payload := map[string]interface{}{
		"model":      model,
		"messages":   []map[string]string{{"role": "user", "content": req.Prompt}},
		"max_tokens": maxTokens,
	}

	body, _ := json.Marshal(payload)

	httpReq, _ := http.NewRequest("POST", p.llmEndpoint+"/v1/messages", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", p.llmAPIKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")

	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return &Response{ID: req.ID, OK: false, Error: err.Error(), Code: -3}
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		return &Response{ID: req.ID, OK: false, Error: string(respBody), Code: resp.StatusCode}
	}

	var result struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
		StopReason string `json:"stop_reason"`
		Usage      struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		} `json:"usage"`
		Model string `json:"model"`
	}

	if err := json.Unmarshal(respBody, &result); err != nil {
		return &Response{ID: req.ID, OK: false, Error: err.Error(), Code: -4}
	}

	content := ""
	if len(result.Content) > 0 {
		content = result.Content[0].Text
	}

	return &Response{
		ID: req.ID,
		OK: true,
		Data: LLMResponse{
			Content:      content,
			Model:        result.Model,
			FinishReason: result.StopReason,
			Usage: struct {
				PromptTokens     int `json:"prompt_tokens"`
				CompletionTokens int `json:"completion_tokens"`
				TotalTokens      int `json:"total_tokens"`
			}{
				PromptTokens:     result.Usage.InputTokens,
				CompletionTokens: result.Usage.OutputTokens,
				TotalTokens:      result.Usage.InputTokens + result.Usage.OutputTokens,
			},
		},
	}
}

func (p *Proxy) anthropicChat(req *Request) *Response {
	model := req.Model
	if model == "" {
		model = "claude-sonnet-4-20250514"
	}

	maxTokens := req.MaxTokens
	if maxTokens == 0 {
		maxTokens = 1000
	}

	messages := make([]map[string]string, len(req.Messages))
	for i, m := range req.Messages {
		messages[i] = map[string]string{"role": m.Role, "content": m.Content}
	}

	payload := map[string]interface{}{
		"model":      model,
		"messages":   messages,
		"max_tokens": maxTokens,
	}

	body, _ := json.Marshal(payload)

	httpReq, _ := http.NewRequest("POST", p.llmEndpoint+"/v1/messages", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", p.llmAPIKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")

	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return &Response{ID: req.ID, OK: false, Error: err.Error(), Code: -3}
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		return &Response{ID: req.ID, OK: false, Error: string(respBody), Code: resp.StatusCode}
	}

	var result struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
		StopReason string `json:"stop_reason"`
		Usage      struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		} `json:"usage"`
		Model string `json:"model"`
	}

	if err := json.Unmarshal(respBody, &result); err != nil {
		return &Response{ID: req.ID, OK: false, Error: err.Error(), Code: -4}
	}

	content := ""
	if len(result.Content) > 0 {
		content = result.Content[0].Text
	}

	return &Response{
		ID: req.ID,
		OK: true,
		Data: LLMResponse{
			Content:      content,
			Model:        result.Model,
			FinishReason: result.StopReason,
			Usage: struct {
				PromptTokens     int `json:"prompt_tokens"`
				CompletionTokens int `json:"completion_tokens"`
				TotalTokens      int `json:"total_tokens"`
			}{
				PromptTokens:     result.Usage.InputTokens,
				CompletionTokens: result.Usage.OutputTokens,
				TotalTokens:      result.Usage.InputTokens + result.Usage.OutputTokens,
			},
		},
	}
}

// Ollama provider (local)
func (p *Proxy) ollamaComplete(req *Request) *Response {
	model := req.Model
	if model == "" {
		model = "llama2"
	}

	payload := map[string]interface{}{
		"model":  model,
		"prompt": req.Prompt,
		"stream": false,
	}

	body, _ := json.Marshal(payload)

	httpReq, _ := http.NewRequest("POST", p.llmEndpoint+"/api/generate", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return &Response{ID: req.ID, OK: false, Error: err.Error(), Code: -3}
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		return &Response{ID: req.ID, OK: false, Error: string(respBody), Code: resp.StatusCode}
	}

	var result struct {
		Response string `json:"response"`
		Model    string `json:"model"`
		Done     bool   `json:"done"`
	}

	if err := json.Unmarshal(respBody, &result); err != nil {
		return &Response{ID: req.ID, OK: false, Error: err.Error(), Code: -4}
	}

	finishReason := "stop"
	if !result.Done {
		finishReason = "length"
	}

	return &Response{
		ID: req.ID,
		OK: true,
		Data: LLMResponse{
			Content:      result.Response,
			Model:        result.Model,
			FinishReason: finishReason,
		},
	}
}

func (p *Proxy) ollamaChat(req *Request) *Response {
	model := req.Model
	if model == "" {
		model = "llama2"
	}

	messages := make([]map[string]string, len(req.Messages))
	for i, m := range req.Messages {
		messages[i] = map[string]string{"role": m.Role, "content": m.Content}
	}

	payload := map[string]interface{}{
		"model":    model,
		"messages": messages,
		"stream":   false,
	}

	body, _ := json.Marshal(payload)

	httpReq, _ := http.NewRequest("POST", p.llmEndpoint+"/api/chat", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return &Response{ID: req.ID, OK: false, Error: err.Error(), Code: -3}
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		return &Response{ID: req.ID, OK: false, Error: string(respBody), Code: resp.StatusCode}
	}

	var result struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
		Model string `json:"model"`
		Done  bool   `json:"done"`
	}

	if err := json.Unmarshal(respBody, &result); err != nil {
		return &Response{ID: req.ID, OK: false, Error: err.Error(), Code: -4}
	}

	finishReason := "stop"
	if !result.Done {
		finishReason = "length"
	}

	return &Response{
		ID: req.ID,
		OK: true,
		Data: LLMResponse{
			Content:      result.Message.Content,
			Model:        result.Model,
			FinishReason: finishReason,
		},
	}
}

// TCP Operations

func (p *Proxy) handleTCPConnect(req *Request) *Response {
	if req.Host == "" {
		return &Response{ID: req.ID, OK: false, Error: "host required", Code: -2}
	}
	if req.Port <= 0 || req.Port > 65535 {
		return &Response{ID: req.ID, OK: false, Error: "invalid port", Code: -2}
	}

	addr := fmt.Sprintf("%s:%d", req.Host, req.Port)
	dialer := net.Dialer{Timeout: 30 * time.Second}
	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return &Response{ID: req.ID, OK: false, Error: err.Error(), Code: -3}
	}

	// Generate connection ID and store
	p.tcpMu.Lock()
	connID := p.nextConnID
	p.nextConnID++
	p.tcpConns[connID] = conn
	p.tcpMu.Unlock()

	localAddr := ""
	remoteAddr := ""
	if conn.LocalAddr() != nil {
		localAddr = conn.LocalAddr().String()
	}
	if conn.RemoteAddr() != nil {
		remoteAddr = conn.RemoteAddr().String()
	}

	return &Response{
		ID: req.ID,
		OK: true,
		Data: TCPConnection{
			ConnID:     connID,
			LocalAddr:  localAddr,
			RemoteAddr: remoteAddr,
		},
	}
}

func (p *Proxy) handleTCPSend(req *Request) *Response {
	p.tcpMu.RLock()
	conn, ok := p.tcpConns[req.ConnID]
	p.tcpMu.RUnlock()

	if !ok {
		return &Response{ID: req.ID, OK: false, Error: "connection not found", Code: -10}
	}

	// Data is base64 encoded
	data, err := base64.StdEncoding.DecodeString(req.Data)
	if err != nil {
		// Try raw string if not base64
		data = []byte(req.Data)
	}

	// Set write deadline
	conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	n, err := conn.Write(data)
	conn.SetWriteDeadline(time.Time{}) // Clear deadline

	if err != nil {
		return &Response{ID: req.ID, OK: false, Error: err.Error(), Code: -3}
	}

	return &Response{
		ID:   req.ID,
		OK:   true,
		Data: map[string]int{"bytes_sent": n},
	}
}

func (p *Proxy) handleTCPRecv(req *Request) *Response {
	p.tcpMu.RLock()
	conn, ok := p.tcpConns[req.ConnID]
	p.tcpMu.RUnlock()

	if !ok {
		return &Response{ID: req.ID, OK: false, Error: "connection not found", Code: -10}
	}

	bufSize := req.Size
	if bufSize <= 0 {
		bufSize = 4096 // Default buffer size
	}
	if bufSize > 10*1024*1024 {
		bufSize = 10 * 1024 * 1024 // Max 10MB
	}

	buf := make([]byte, bufSize)

	// Set read deadline
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	n, err := conn.Read(buf)
	conn.SetReadDeadline(time.Time{}) // Clear deadline

	if err != nil {
		if err == io.EOF {
			// Connection closed by peer
			return &Response{
				ID: req.ID,
				OK: true,
				Data: TCPRecvResponse{
					Data:   "",
					Length: 0,
				},
			}
		}
		// Check for timeout (not an error, just no data)
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return &Response{
				ID: req.ID,
				OK: true,
				Data: TCPRecvResponse{
					Data:   "",
					Length: 0,
				},
			}
		}
		return &Response{ID: req.ID, OK: false, Error: err.Error(), Code: -3}
	}

	// Return data as base64
	return &Response{
		ID: req.ID,
		OK: true,
		Data: TCPRecvResponse{
			Data:   base64.StdEncoding.EncodeToString(buf[:n]),
			Length: n,
		},
	}
}

func (p *Proxy) handleTCPClose(req *Request) *Response {
	p.tcpMu.Lock()
	conn, ok := p.tcpConns[req.ConnID]
	if ok {
		delete(p.tcpConns, req.ConnID)
	}
	p.tcpMu.Unlock()

	if !ok {
		return &Response{ID: req.ID, OK: false, Error: "connection not found", Code: -10}
	}

	err := conn.Close()
	if err != nil {
		return &Response{ID: req.ID, OK: false, Error: err.Error(), Code: -3}
	}

	return &Response{
		ID:   req.ID,
		OK:   true,
		Data: map[string]bool{"closed": true},
	}
}

// Server handling

func (p *Proxy) ServeConn(conn io.ReadWriteCloser) {
	defer conn.Close()

	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 1024*1024), 10*1024*1024) // 10MB max line

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var req Request
		if err := json.Unmarshal(line, &req); err != nil {
			resp := Response{ID: "", OK: false, Error: "invalid JSON: " + err.Error(), Code: -1}
			respBytes, _ := json.Marshal(resp)
			conn.Write(append(respBytes, '\n'))
			continue
		}

		resp := p.Handle(&req)
		respBytes, _ := json.Marshal(resp)
		conn.Write(append(respBytes, '\n'))
	}
}

func main() {
	var (
		socketPath  = flag.String("socket", "/tmp/akproxy.sock", "Unix socket path")
		virtioPath  = flag.String("virtio", "", "Virtio-serial device path (e.g., /dev/vport0p1)")
		allowedDirs = flag.String("allowed-dirs", "/tmp", "Comma-separated allowed directories")
		llmEndpoint = flag.String("llm-endpoint", "", "LLM API endpoint (e.g., https://api.openai.com)")
		llmAPIKey   = flag.String("llm-api-key", "", "LLM API key (or use AK_LLM_API_KEY env)")
		llmProvider = flag.String("llm-provider", "openai", "LLM provider: openai, anthropic, ollama")
	)
	flag.Parse()

	// Get API key from env if not provided
	apiKey := *llmAPIKey
	if apiKey == "" {
		apiKey = os.Getenv("AK_LLM_API_KEY")
	}
	if apiKey == "" {
		apiKey = os.Getenv("OPENAI_API_KEY")
	}
	if apiKey == "" {
		apiKey = os.Getenv("ANTHROPIC_API_KEY")
	}

	config := &Config{
		AllowedDirs: strings.Split(*allowedDirs, ","),
		LLMEndpoint: *llmEndpoint,
		LLMAPIKey:   apiKey,
		LLMProvider: *llmProvider,
	}

	proxy := NewProxy(config)

	// If virtio path provided, use that
	if *virtioPath != "" {
		fmt.Printf("Opening virtio-serial device: %s\n", *virtioPath)
		for {
			f, err := os.OpenFile(*virtioPath, os.O_RDWR, 0)
			if err != nil {
				fmt.Printf("Failed to open virtio device: %v, retrying...\n", err)
				time.Sleep(time.Second)
				continue
			}
			fmt.Println("Connected to virtio-serial")
			proxy.ServeConn(f)
			fmt.Println("Connection closed, reopening...")
		}
	}

	// Otherwise use Unix socket
	os.Remove(*socketPath)
	listener, err := net.Listen("unix", *socketPath)
	if err != nil {
		fmt.Printf("Failed to listen on %s: %v\n", *socketPath, err)
		os.Exit(1)
	}
	defer listener.Close()

	fmt.Printf("Authority Kernel Proxy listening on %s\n", *socketPath)
	fmt.Printf("LLM Provider: %s, Endpoint: %s\n", *llmProvider, *llmEndpoint)
	fmt.Printf("Allowed directories: %v\n", config.AllowedDirs)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			fmt.Printf("Accept error: %v\n", err)
			continue
		}
		go proxy.ServeConn(conn)
	}
}
