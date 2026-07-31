// Copyright 2022 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package handlers

import (
	"github.com/gojue/ecapture/internal/domain"
	"github.com/gojue/ecapture/internal/errors"
	"github.com/gojue/ecapture/internal/output/encoders"
	"github.com/gojue/ecapture/internal/output/writers"
)

// TextHandler handles events by writing their encoded output to a destination.
// It delegates formatting to the event itself via String() or StringHex() methods.
type TextHandler struct {
	writer          writers.OutputWriter
	encoder         encoders.Encoder
	suppressPackets bool
}

func (h *TextHandler) Writer() writers.OutputWriter {
	return h.writer
}

// NewTextHandler creates a new TextHandler with the provided writer.
// Events format themselves via String() or StringHex() methods.
func NewTextHandler(writer writers.OutputWriter, useHex bool) *TextHandler {
	if writer == nil {
		writer = writers.NewStdoutWriter()
	}
	return &TextHandler{
		writer:  writer,
		encoder: encoders.NewPlainEncoder(useHex),
	}
}

// NewEncodedTextHandler creates an event handler with an explicit encoder.
// The historical name is retained because this handler still owns the
// line-oriented event output channel, even when the selected encoding is JSON.
func NewEncodedTextHandler(
	writer writers.OutputWriter,
	encoder encoders.Encoder,
) *TextHandler {
	if writer == nil {
		writer = writers.NewStdoutWriter()
	}
	if encoder == nil {
		encoder = encoders.NewPlainEncoder(false)
	}
	return &TextHandler{writer: writer, encoder: encoder}
}

// SuppressPacketEvents prevents raw TC packets from being duplicated into the
// line-oriented event sink. PCAP-only captures use this when no explicit event
// collector was requested; otherwise remote logs can become traffic that is
// captured and logged again in a self-amplifying loop.
func (h *TextHandler) SuppressPacketEvents() {
	h.suppressPackets = true
}

// Handle processes an event and writes its formatted output.
// The event is responsible for its own formatting via String() or StringHex() methods.
func (h *TextHandler) Handle(event domain.Event) error {
	if event == nil {
		return errors.New(errors.ErrCodeEventValidation, "event cannot be nil")
	}
	if h.suppressPackets {
		if _, packet := event.(PacketEvent); packet {
			return nil
		}
	}

	output, err := h.encoder.Encode(event)
	if err != nil {
		return errors.Wrap(errors.ErrCodeEventDispatch, "failed to encode event output", err)
	}

	// Skip empty output (event not ready or filtered out)
	if len(output) == 0 {
		return nil
	}

	// Ensure output ends with newline for readability
	if output[len(output)-1] != '\n' {
		output = append(output, '\n')
	}

	// Write to output destination
	_, err = h.writer.Write(output)
	if err != nil {
		return errors.Wrap(errors.ErrCodeEventDispatch, "failed to write event output", err)
	}

	return nil
}

// Close closes the handler and releases resources.
func (h *TextHandler) Close() error {
	if h.writer == nil {
		return nil
	}
	return h.writer.Close()
}

// Name returns the handler's identifier.
func (h *TextHandler) Name() string {
	return ModeText
}
