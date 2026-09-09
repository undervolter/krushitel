//go:build windows

package scanner

// getUlimit — на Windows RLIMIT_NOFILE неприменим к Go-сокетам; безопасный
// фиксированный кап воркеров.
func getUlimit() uint64 {
	return 4000
}
