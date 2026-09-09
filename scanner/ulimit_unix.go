//go:build !windows

package scanner

import "syscall"

// getUlimit — кап воркеров по лимиту fd (каждый воркер = UDP-сокет).
func getUlimit() uint64 {
	var rLimit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit); err != nil {
		return 1024
	}
	return rLimit.Cur
}
