// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kvstore

import (
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/logging"
)

var (
	// Debugging can be enabled at compile with:
	// -ldflags "-X "github.com/cilium/cilium/pkg/kvstore".Debug=true"
	Debug string

	// force-enable tracing
	traceEnabled bool = true
)

// EnableTracing enables kvstore tracing
func EnableTracing() {
	traceEnabled = true
}

// Trace is used to trace kvstore debug messages
func Trace(format string, err error, fields logrus.Fields, a ...interface{}) {
	if traceEnabled {
		// Set tracing to info level for better debugging
		log.WithError(err).WithFields(fields).Infof(format)
	}
}

func init() {
	if strings.ToLower(Debug) == "true" {
		logging.DefaultLogger.SetLevel(logrus.DebugLevel)
		traceEnabled = true
	}
}
