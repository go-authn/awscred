// SPDX-License-Identifier: BSD-3-Clause

//go:build !unix

package credproc

import "os"

// On Windows a file's mode says nothing about who can write it; the user's
// profile directory's ACL is what keeps the cache private (as servercert does).
func checkCacheDir(string) error { return nil }

func checkCacheFile(os.FileInfo) error { return nil }
