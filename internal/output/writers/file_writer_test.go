// Copyright 2026 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package writers

import (
	"path/filepath"
	"testing"
)

func TestFileWriterCloseIsIdempotent(t *testing.T) {
	writer, err := NewFileWriter(FileWriterConfig{
		Path:       filepath.Join(t.TempDir(), "events.jsonl"),
		BufferSize: 4096,
		Truncate:   true,
	})
	if err != nil {
		t.Fatalf("NewFileWriter() error = %v", err)
	}
	if _, err := writer.Write([]byte("event\n")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("first Close() error = %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
}
