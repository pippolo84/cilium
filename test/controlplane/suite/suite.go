// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package suite

import (
	"os"
	"strings"
	"testing"
)

type testCase struct {
	name string
	test func(t *testing.T)
}

var allTestCases []testCase

func AddTestCase(name string, fun func(t *testing.T)) {
	//FIXME:
	if !strings.Contains(name, "Operator") {
		return
	}
	allTestCases = append(allTestCases, testCase{name, fun})
}

func RunSuite(t *testing.T) {
	ParseFlags()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range allTestCases {
		t.Run(tc.name, tc.test)

		// Switch back to test root
		// FIXME: maybe just consider embedding instead?
		os.Chdir(cwd)
	}
}
