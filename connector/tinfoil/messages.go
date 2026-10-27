package tinfoil

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type object = map[string]any

func messageResponse(r *http.Request, resp *http.Response, model any, streaming bool) (*http.Response, error) {
	if resp.StatusCode >= 400 {
		defer resp.Body.Close()
		var failure struct {
			Error struct {
				Message string `json:"message"`
				Type    string `json:"type"`
			} `json:"error"`
		}
		if json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&failure) != nil || failure.Error.Message == "" {
			failure.Error.Message = fmt.Sprintf("Tinfoil returned HTTP %d", resp.StatusCode)
		}
		converted := messageError(r, resp.StatusCode, "api_error", failure.Error.Message)
		if retry := resp.Header.Get("Retry-After"); retry != "" {
			converted.Header.Set("Retry-After", retry)
		}
		return converted, nil
	}
	if !streaming {
		defer resp.Body.Close()
		var result chatChunk
		if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&result); err != nil {
			return nil, err
		}
		if len(result.Choices) != 1 {
			return nil, errors.New("Tinfoil returned no completion")
		}
		choice := result.Choices[0]
		content := []object{}
		if choice.Message.Reasoning != "" {
			content = append(content, object{"type": "thinking", "thinking": choice.Message.Reasoning, "signature": ""})
		}
		if choice.Message.Content != "" {
			content = append(content, object{"type": "text", "text": choice.Message.Content})
		}
		for _, call := range choice.Message.ToolCalls {
			var args object
			if err := json.Unmarshal([]byte(call.Function.Arguments), &args); err != nil {
				return nil, err
			}
			content = append(content, object{"type": "tool_use", "id": call.ID, "name": call.Function.Name, "input": args})
		}
		return messageJSON(r, resp.StatusCode, object{"id": result.ID, "type": "message", "role": "assistant", "model": model, "content": content, "stop_reason": stopReason(choice.FinishReason), "stop_sequence": nil, "usage": result.Usage.anthropic()}), nil
	}
	reader, writer := io.Pipe()
	original := resp.Body
	go func() {
		defer original.Close()
		writer.CloseWithError(streamMessages(writer, original, model))
	}()
	resp.Body = &messageStream{PipeReader: reader, upstream: original}
	resp.ContentLength = -1
	resp.Header.Del("Content-Length")
	resp.Header.Del("Content-Encoding")
	resp.Header.Set("Content-Type", "text/event-stream")
	return resp, nil
}

type messageStream struct {
	*io.PipeReader
	upstream io.ReadCloser
}

func (s *messageStream) Close() error { s.PipeReader.Close(); return s.upstream.Close() }

func messageJSON(r *http.Request, status int, body object) *http.Response {
	raw, _ := json.Marshal(body)
	return &http.Response{StatusCode: status, Status: http.StatusText(status), Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(bytes.NewReader(raw)), ContentLength: int64(len(raw)), Request: r}
}
func messageError(r *http.Request, status int, kind, message string) *http.Response {
	return messageJSON(r, status, object{"type": "error", "error": object{"type": kind, "message": message}})
}

func chatRequest(in object) (object, error) {
	out := object{"model": in["model"]}
	for _, key := range []string{"max_tokens", "temperature", "top_p", "top_k", "stream"} {
		if v, ok := in[key]; ok {
			out[key] = v
		}
	}
	if v, ok := in["stop_sequences"]; ok {
		out["stop"] = v
	}
	if in["stream"] == true {
		out["stream_options"] = object{"include_usage": true}
	}
	messages := []object{}
	if system, ok := in["system"]; ok {
		blocks, err := chatContent(system)
		if err != nil {
			return nil, err
		}
		messages = append(messages, object{"role": "system", "content": blocks})
	}
	history, ok := in["messages"].([]any)
	if !ok {
		return nil, errors.New("messages must be an array")
	}
	for _, item := range history {
		msg, ok := item.(map[string]any)
		if !ok {
			return nil, errors.New("invalid message")
		}
		// Claude Code 2.1.260 also sends system messages in the history array.
		switch msg["role"] {
		case "assistant", "user", "system", "developer":
		default:
			return nil, errors.New("invalid message role")
		}
		current := object{"role": msg["role"]}
		if text, ok := msg["content"].(string); ok {
			current["content"] = text
		} else {
			blocks, ok := msg["content"].([]any)
			if !ok {
				return nil, errors.New("content must be text or an array")
			}
			ordinary, calls := []any{}, []object{}
			reasoning := ""
			for _, item := range blocks {
				block, ok := item.(map[string]any)
				if !ok {
					return nil, errors.New("invalid content block")
				}
				switch block["type"] {
				case "tool_use":
					if msg["role"] != "assistant" {
						return nil, errors.New("tool_use requires an assistant message")
					}
					args, err := json.Marshal(block["input"])
					if err != nil {
						return nil, err
					}
					calls = append(calls, object{"id": block["id"], "type": "function", "function": object{"name": block["name"], "arguments": string(args)}})
				case "tool_result":
					if msg["role"] != "user" {
						return nil, errors.New("tool_result requires a user message")
					}
					content, err := chatContent(block["content"])
					if err != nil {
						return nil, err
					}
					if block["is_error"] == true {
						switch value := content.(type) {
						case string:
							content = "Tool error: " + value
						case []object:
							content = append([]object{{"type": "text", "text": "Tool error:"}}, value...)
						}
					}
					messages = append(messages, object{"role": "tool", "tool_call_id": block["tool_use_id"], "content": content})
				case "thinking":
					text, _ := block["thinking"].(string)
					reasoning += text
				default:
					ordinary = append(ordinary, block)
				}
			}
			if len(ordinary) > 0 {
				content, err := chatContent(ordinary)
				if err != nil {
					return nil, err
				}
				current["content"] = content
			}
			if len(calls) > 0 {
				current["tool_calls"] = calls
			}
			if reasoning != "" {
				current["reasoning_content"] = reasoning
			}
		}
		if len(current) > 1 {
			messages = append(messages, current)
		}
	}
	out["messages"] = messages
	if tools, ok := in["tools"].([]any); ok && len(tools) > 0 {
		converted := []object{}
		for _, item := range tools {
			tool, ok := item.(map[string]any)
			if !ok || tool["input_schema"] == nil || tool["name"] == nil {
				return nil, errors.New("only client function tools are supported")
			}
			fn := object{"name": tool["name"], "parameters": tool["input_schema"]}
			if v, ok := tool["description"]; ok {
				fn["description"] = v
			}
			converted = append(converted, object{"type": "function", "function": fn})
		}
		out["tools"] = converted
	}
	if choice, ok := in["tool_choice"].(map[string]any); ok {
		switch choice["type"] {
		case "auto", "none":
			out["tool_choice"] = choice["type"]
		case "any":
			out["tool_choice"] = "required"
		case "tool":
			out["tool_choice"] = object{"type": "function", "function": object{"name": choice["name"]}}
		default:
			return nil, errors.New("unsupported tool choice")
		}
		if disabled, ok := choice["disable_parallel_tool_use"].(bool); ok {
			out["parallel_tool_calls"] = !disabled
		}
	}
	return out, nil
}

func chatContent(value any) (any, error) {
	if value == nil {
		return "", nil
	}
	if text, ok := value.(string); ok {
		return text, nil
	}
	blocks, ok := value.([]any)
	if !ok {
		return nil, errors.New("invalid content")
	}
	result := []object{}
	for _, item := range blocks {
		block, ok := item.(map[string]any)
		if !ok {
			return nil, errors.New("invalid content block")
		}
		switch block["type"] {
		case "text":
			result = append(result, object{"type": "text", "text": block["text"]})
		case "image":
			source, _ := block["source"].(map[string]any)
			var url string
			switch source["type"] {
			case "url":
				url, _ = source["url"].(string)
			case "base64":
				media, _ := source["media_type"].(string)
				data, _ := source["data"].(string)
				url = "data:" + media + ";base64," + data
			default:
				return nil, errors.New("unsupported image source")
			}
			result = append(result, object{"type": "image_url", "image_url": object{"url": url}})
		default:
			return nil, fmt.Errorf("unsupported Messages content type: %v", block["type"])
		}
	}
	return result, nil
}

type chatUsage struct {
	Prompt     int `json:"prompt_tokens"`
	Completion int `json:"completion_tokens"`
	Details    struct {
		Cached int `json:"cached_tokens"`
	} `json:"prompt_tokens_details"`
}

func (u chatUsage) anthropic() object {
	return object{"input_tokens": max(0, u.Prompt-u.Details.Cached), "output_tokens": u.Completion, "cache_read_input_tokens": u.Details.Cached, "cache_creation_input_tokens": 0}
}

type chatTool struct {
	Index    int    `json:"index"`
	ID       string `json:"id"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}
type chatDelta struct {
	Content   string     `json:"content"`
	Reasoning string     `json:"reasoning_content"`
	ToolCalls []chatTool `json:"tool_calls"`
}
type chatChunk struct {
	ID      string `json:"id"`
	Choices []struct {
		Delta        chatDelta `json:"delta"`
		Message      chatDelta `json:"message"`
		FinishReason string    `json:"finish_reason"`
	} `json:"choices"`
	Usage chatUsage       `json:"usage"`
	Error json.RawMessage `json:"error"`
}

func stopReason(reason string) string {
	switch reason {
	case "tool_calls", "function_call":
		return "tool_use"
	case "length":
		return "max_tokens"
	default:
		return "end_turn"
	}
}

func streamMessages(w io.Writer, r io.Reader, model any) error {
	emit := func(kind string, body object) error {
		body["type"] = kind
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", kind, raw)
		return err
	}
	started, finished := false, false
	next, textIndex, thinkingIndex := 0, -1, -1
	tools := map[int]int{}
	open := []int{}
	usage, reason := chatUsage{}, ""
	start := func(body object) (int, error) {
		index := next
		next++
		open = append(open, index)
		return index, emit("content_block_start", object{"index": index, "content_block": body})
	}
	process := func(data string) error {
		if data == "[DONE]" {
			finished = true
			return nil
		}
		var chunk chatChunk
		if err := json.Unmarshal([]byte(data), &chunk); err != nil {
			return err
		}
		if len(chunk.Error) > 0 {
			return errors.New("Tinfoil stream returned an error")
		}
		if !started {
			if err := emit("message_start", object{"message": object{"id": chunk.ID, "type": "message", "role": "assistant", "model": model, "content": []any{}, "stop_reason": nil, "stop_sequence": nil, "usage": chunk.Usage.anthropic()}}); err != nil {
				return err
			}
			started = true
		}
		if chunk.Usage.Prompt > 0 || chunk.Usage.Completion > 0 {
			usage = chunk.Usage
		}
		for _, choice := range chunk.Choices {
			if choice.FinishReason != "" {
				reason = choice.FinishReason
			}
			for _, part := range []struct {
				text, kind, key string
				index           *int
			}{
				{choice.Delta.Reasoning, "thinking", "thinking", &thinkingIndex}, {choice.Delta.Content, "text", "text", &textIndex},
			} {
				if part.text == "" {
					continue
				}
				if *part.index < 0 {
					var err error
					*part.index, err = start(object{"type": part.kind, part.key: ""})
					if err != nil {
						return err
					}
				}
				if err := emit("content_block_delta", object{"index": *part.index, "delta": object{"type": part.kind + "_delta", part.key: part.text}}); err != nil {
					return err
				}
			}
			for _, call := range choice.Delta.ToolCalls {
				index, exists := tools[call.Index]
				if !exists {
					if call.ID == "" || call.Function.Name == "" {
						return errors.New("Tinfoil tool stream is missing its identity")
					}
					var err error
					index, err = start(object{"type": "tool_use", "id": call.ID, "name": call.Function.Name, "input": object{}})
					if err != nil {
						return err
					}
					tools[call.Index] = index
				}
				if call.Function.Arguments != "" {
					if err := emit("content_block_delta", object{"index": index, "delta": object{"type": "input_json_delta", "partial_json": call.Function.Arguments}}); err != nil {
						return err
					}
				}
			}
		}
		return nil
	}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 4096), 8<<20)
	var data []string
	eventBytes := 0
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			if len(data) > 0 {
				if err := process(strings.Join(data, "\n")); err != nil {
					return err
				}
				data = nil
				eventBytes = 0
			}
			if finished {
				break
			}
		} else if value, ok := strings.CutPrefix(line, "data:"); ok {
			eventBytes += len(value)
			if eventBytes > 8<<20 {
				return errors.New("Tinfoil stream event is too large")
			}
			data = append(data, strings.TrimPrefix(value, " "))
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if len(data) > 0 {
		if err := process(strings.Join(data, "\n")); err != nil {
			return err
		}
	}
	if !started || !finished || reason == "" {
		return io.ErrUnexpectedEOF
	}
	if thinkingIndex >= 0 {
		if err := emit("content_block_delta", object{"index": thinkingIndex, "delta": object{"type": "signature_delta", "signature": ""}}); err != nil {
			return err
		}
	}
	for _, index := range open {
		if err := emit("content_block_stop", object{"index": index}); err != nil {
			return err
		}
	}
	if err := emit("message_delta", object{"delta": object{"stop_reason": stopReason(reason), "stop_sequence": nil}, "usage": usage.anthropic()}); err != nil {
		return err
	}
	return emit("message_stop", object{})
}
