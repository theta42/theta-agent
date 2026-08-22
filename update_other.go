//go:build !windows

package main

import (
	"fmt"
	"os"
)

// swapUpdatedBinary installs a freshly downloaded binary at binPath. On unix
// the running executable can be renamed over freely (the inode stays alive),
// so a plain rename suffices; the caller restarts the service afterwards.
func swapUpdatedBinary(_ *Config, tmpPath, binPath string) (bool, error) {
	if err := os.Rename(tmpPath, binPath); err != nil {
		return false, fmt.Errorf("replace %s: %w", binPath, err)
	}
	return false, nil
}
