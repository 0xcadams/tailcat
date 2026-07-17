// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build ts_omit_ssh

package main

import (
	"os"

	"tailscale.com/types/logger"
)

const tailCatSSHEnabled = false

func clientSSHMode(logf logger.Logf) {
	logf("ssh support not compiled in")
	os.Exit(1)
}
