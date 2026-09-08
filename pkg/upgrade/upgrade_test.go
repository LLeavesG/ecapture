// Copyright 2024 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
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

package upgrade

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCheckLatest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") != "ecapture-test" || r.Header.Get("Accept") != "application/json" {
			t.Error("release request is missing its API headers")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"tag_name":"v0.9.2","assets":[{"name":"ecapture-v0.9.2-linux-amd64.tar.gz","browser_download_url":"https://example.test/release.tar.gz"}]}`))
	}))
	defer server.Close()
	release, err := GetLatestVersion("ecapture-test", server.URL, context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if release.TagName != "v0.9.2" || len(release.Assets) != 1 || release.Assets[0].BrowserDownloadURL != "https://example.test/release.tar.gz" {
		t.Fatalf("unexpected release: %+v", release)
	}
	if comparison, err := CheckVersion("v0.9.1", release.TagName); err != nil || comparison >= 0 {
		t.Fatalf("expected an upgrade, comparison=%d error=%v", comparison, err)
	}
}

func TestInvalidReleaseURLReturnsError(t *testing.T) {
	if _, err := GetLatestVersion("ecapture-test", "://invalid", context.Background()); err == nil {
		t.Fatal("invalid URL was accepted")
	}
}

func TestReleaseErrorClosesResponseBody(t *testing.T) {
	closed := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		close(closed)
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, err := GetLatestVersion("ecapture-test", server.URL, ctx); err == nil {
		t.Fatal("HTTP error was accepted")
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("error response body was left open")
	}
}

func TestInvalidReleaseJSONReturnsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not JSON"))
	}))
	defer server.Close()
	if _, err := GetLatestVersion("ecapture-test", server.URL, context.Background()); err == nil {
		t.Fatal("invalid JSON was accepted")
	}
}
