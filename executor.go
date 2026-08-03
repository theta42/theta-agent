package main

import (
	"os"
	"os/exec"
)

// Executor abstracts system operations to allow for easy mocking in tests.
type Executor interface {
	// Execute runs a system command and returns combined stdout/stderr.
	Execute(command string, args ...string) ([]byte, error)

	// WriteFile writes data to a file with specified permissions.
	WriteFile(path string, data []byte, perm os.FileMode) error

	// ReadFile reads the content of a file.
	ReadFile(path string) ([]byte, error)
}

// SystemExecutor is the production implementation that performs real system calls.
type SystemExecutor struct{}

// Execute runs a real system command.
func (s *SystemExecutor) Execute(command string, args ...string) ([]byte, error) {
	cmd := exec.Command(command, args...)
	return cmd.CombinedOutput()
}

// WriteFile performs a real file write.
func (s *SystemExecutor) WriteFile(path string, data []byte, perm os.FileMode) error {
	return os.WriteFile(path, data, perm)
}

// ReadFile performs a real file read.
func (s *SystemExecutor) ReadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}
