// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package wasmbuild builds the tailcat web WebAssembly binary and
// the distribution directory of static files that servers of the web
// app need. It is shared by cmd/tailcat-web, cmd/tailcat-webdist,
// and the browser integration tests.
package wasmbuild

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"github.com/klauspost/compress/zstd"
	"tailscale.com/feature/featuretags"
)

// GoRoot returns the GOROOT of the go command in $PATH.
func GoRoot() (string, error) {
	out, err := exec.Command("go", "env", "GOROOT").Output()
	if err != nil {
		return "", fmt.Errorf("go env GOROOT: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

// WasmExecJS returns the path to the Go toolchain's wasm_exec.js,
// the JavaScript support file needed to run Go wasm binaries.
func WasmExecJS() (string, error) {
	goroot, err := GoRoot()
	if err != nil {
		return "", err
	}
	return filepath.Join(goroot, "lib", "wasm", "wasm_exec.js"), nil
}

// keep is the set of tailscale.com feature tags the wasm build needs
// linked; every other feature in the featuretags registry is excluded
// via its ts_omit_ build tag, following cmd/tsconnect/wasmbuild.
// tailcat uses the data plane only, so it needs little: netstack for
// userspace TCP (wasm has no kernel TUN) and nothing else. Omitting
// the rest shrinks the wasm binary by about 6 MB (18%).
var keep = []featuretags.FeatureTag{
	"netstack",
}

// Tags returns the comma-joined -tags value for the wasm build,
// sorted so the same source tree always produces the same wasm bytes.
func Tags() string {
	keepSet := map[featuretags.FeatureTag]bool{}
	for _, ft := range keep {
		for dep := range featuretags.Requires(ft) {
			keepSet[dep] = true
		}
	}
	tags := []string{"osusergo", "netgo", "omitidna", "omitpemdecrypt"}
	for ft := range featuretags.Features {
		if ft == "" || !ft.IsOmittable() {
			continue
		}
		if !keepSet[ft] {
			tags = append(tags, ft.OmitTag())
		}
	}
	slices.Sort(tags)
	return strings.Join(tags, ",")
}

// Build compiles the Go package in pkgDir for js/wasm and writes the
// binary to outPath.
func Build(pkgDir, outPath string) error {
	cmd := exec.Command("go", "build", "-tags", Tags(), "-ldflags=-s -w", "-o", outPath, pkgDir)
	cmd.Env = append(os.Environ(), "GOOS=js", "GOARCH=wasm")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("go build %v: %v\n%s", pkgDir, err, out)
	}
	return nil
}

// Dist builds the complete set of static files a server needs to
// serve the web app: main.wasm (compiled from the Go package in
// webDir, with precompressed main.wasm.zst and main.wasm.gz
// variants), the toolchain's wasm_exec.js, and index.html and app.js
// copied from webDir. It writes them all to outDir, creating it if
// needed.
func Dist(webDir, outDir string) error {
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return err
	}
	pkgArg := webDir
	if !filepath.IsAbs(pkgArg) {
		pkgArg = "./" + filepath.ToSlash(pkgArg)
	}
	wasmPath := filepath.Join(outDir, "main.wasm")
	if err := Build(pkgArg, wasmPath); err != nil {
		return err
	}
	if err := compressWasm(wasmPath); err != nil {
		return err
	}
	wasmExecJS, err := WasmExecJS()
	if err != nil {
		return err
	}
	if err := copyFile(wasmExecJS, filepath.Join(outDir, "wasm_exec.js")); err != nil {
		return err
	}
	for _, name := range []string{"index.html", "app.js"} {
		if err := copyFile(filepath.Join(webDir, name), filepath.Join(outDir, name)); err != nil {
			return err
		}
	}
	return nil
}

func copyFile(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, b, 0644)
}

// compressWasm writes path.zst and path.gz next to path.
func compressWasm(path string) error {
	src, err := os.Open(path)
	if err != nil {
		return err
	}
	defer src.Close()

	zf, err := os.Create(path + ".zst")
	if err != nil {
		return err
	}
	defer zf.Close()
	zw, err := zstd.NewWriter(zf)
	if err != nil {
		return err
	}
	if _, err := io.Copy(zw, src); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}

	if _, err := src.Seek(0, io.SeekStart); err != nil {
		return err
	}
	gf, err := os.Create(path + ".gz")
	if err != nil {
		return err
	}
	defer gf.Close()
	gw := gzip.NewWriter(gf)
	if _, err := io.Copy(gw, src); err != nil {
		return err
	}
	return gw.Close()
}
