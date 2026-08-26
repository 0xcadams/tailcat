// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tailscale.com/tstest/integration"
)

// TestPipeMode runs the built tailcat binary in its two stdin/stdout
// pipe modes against a local DERP server, emulating a pipeline like
// "tailcat | tar -zx" on the server side and "tar -zc | tailcat
// <blob>" on the client side. Both processes must exit on their own
// once the client's stdin hits EOF: the server must see the client's
// half-close as EOF, and the client must see the server's close (the
// server must not exit before its FIN is delivered, which once made
// clients hang forever).
func TestPipeMode(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "tailcat")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	dm := integration.RunDERPAndSTUN(t, t.Logf, "127.0.0.1")
	dmJSON, err := json.Marshal(dm)
	if err != nil {
		t.Fatal(err)
	}
	dmSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(dmJSON)
	}))
	defer dmSrv.Close()

	addrFile := filepath.Join(t.TempDir(), "addr")

	// Point os.UserCacheDir at a temp dir so test runs don't litter
	// the real user cache with DERP map entries keyed by this test's
	// ephemeral --derpmap-url.
	cacheDir := t.TempDir()
	cacheEnv := []string{
		"XDG_CACHE_HOME=" + cacheDir, // Linux
		"HOME=" + cacheDir,           // macOS
		"LocalAppData=" + cacheDir,   // Windows
	}

	server := exec.Command(bin, "--key=new", "--derpmap-url="+dmSrv.URL)
	server.Env = append(append(os.Environ(), cacheEnv...), "TAILCAT_ADDR_FILE="+addrFile)
	serverOut, err := server.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var serverErr bytes.Buffer
	server.Stderr = &serverErr
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	defer server.Process.Kill()

	var blob string
	deadline := time.Now().Add(30 * time.Second)
	for blob == "" {
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for addr file; server stderr:\n%s", serverErr.String())
		}
		b, err := os.ReadFile(addrFile)
		if err == nil && len(b) > 0 {
			blob = strings.TrimSpace(string(b))
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Logf("server blob: %s", blob)

	client := exec.Command(bin, "--key=new", "--derpmap-url="+dmSrv.URL, blob)
	client.Env = append(os.Environ(), cacheEnv...)
	const payload = "pretend this is a tarball"
	client.Stdin = strings.NewReader(payload)
	var clientOut, clientErr bytes.Buffer
	client.Stdout = &clientOut
	client.Stderr = &clientErr
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	defer client.Process.Kill()

	// Emulate "tar -zxv" on the server side: read server stdout until EOF.
	serverGotEOF := make(chan string, 1)
	go func() {
		all, _ := io.ReadAll(serverOut)
		serverGotEOF <- string(all)
	}()

	select {
	case got := <-serverGotEOF:
		t.Logf("server stdout closed; got %q", got)
		if got != payload {
			t.Errorf("server got %q; want %q", got, payload)
		}
	case <-time.After(30 * time.Second):
		t.Fatalf("server side never saw EOF after 30s\nserver stderr:\n%s\nclient stderr:\n%s", serverErr.String(), clientErr.String())
	}

	clientDone := make(chan error, 1)
	go func() { clientDone <- client.Wait() }()
	select {
	case err := <-clientDone:
		if err != nil {
			t.Errorf("client exited with error: %v\nclient stderr:\n%s", err, clientErr.String())
		}
	case <-time.After(15 * time.Second):
		t.Errorf("client did not exit within 15s of the transfer completing\nclient stderr:\n%s", clientErr.String())
	}

	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Wait() }()
	select {
	case err := <-serverDone:
		if err != nil {
			t.Errorf("server exited with error: %v\nserver stderr:\n%s", err, serverErr.String())
		}
	case <-time.After(15 * time.Second):
		t.Errorf("server did not exit within 15s of the transfer completing\nserver stderr:\n%s", serverErr.String())
	}
}
