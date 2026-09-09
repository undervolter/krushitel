package cloud

import "os"

func readFileBytes(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func create(path string) (*os.File, error) {
	return os.Create(path)
}
