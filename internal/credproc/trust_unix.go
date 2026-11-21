// SPDX-License-Identifier: BSD-3-Clause

//go:build unix

package credproc

import (
	"fmt"
	"os"
	"syscall"
)

// checkCacheDir refuses a directory in which somebody else could put or replace
// a file: not owned by this user (unless it is sticky, like /tmp, where the
// file's own owner is checked), or writable by group or other without the
// sticky bit.
func checkCacheDir(dir string) error {
	fi, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	sticky := fi.Mode()&os.ModeSticky != 0
	if fi.Mode().Perm()&0o022 != 0 && !sticky {
		return fmt.Errorf("%s is writable by group or other (mode %o): a cached credential in it cannot be trusted", dir, fi.Mode().Perm())
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Getuid() && !sticky {
		return fmt.Errorf("%s is owned by uid %d, not by this user", dir, st.Uid)
	}
	return nil
}

// checkCacheFile refuses a cache file that is not a regular file of this
// user's, or that group or other can write.
func checkCacheFile(fi os.FileInfo) error {
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("cache file is not a regular file (%s)", fi.Mode().Type())
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("cache file is writable by group or other (mode %o)", fi.Mode().Perm())
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Getuid() {
		return fmt.Errorf("cache file is owned by uid %d, not by this user", st.Uid)
	}
	return nil
}
