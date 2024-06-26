// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package node

import (
	"os"
	"strings"
)

var bootIDFilePath = "/proc/sys/kernel/random/boot_id"

func init() {
	bootID, err := os.ReadFile(bootIDFilePath)
	if err != nil {
		log.WithError(err).Warnf("Could not read boot id from %s", bootIDFilePath)
		return
	}
	localBootID = strings.TrimSpace(string(bootID))
}
