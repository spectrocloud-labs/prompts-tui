// Package mocks contains mock implementations of the interfaces in the prompts package for testing purposes.
package mocks

import (
	"os"
)

// CommandExecutor is an interface for executing commands.
type CommandExecutor interface {
	Start() error
	Wait() error
}

// MockFileEditor is a mock implementation of the FileEditor interface for testing purposes.
type MockFileEditor struct {
	FileContents []string
	filename     string
}

// Start writes the next value in the FileContents slice to the file.
func (m *MockFileEditor) Start() error {
	if err := os.WriteFile(m.filename, []byte(m.FileContents[0]), 0600); err != nil {
		return err
	}
	m.FileContents = m.FileContents[1:]
	return nil
}

// Wait is a no-op to satisfy the CommandExecutor interface.
func (m *MockFileEditor) Wait() error {
	return nil
}

// GetCmdExecutor returns a CommandExecutor that writes to the given filename.
func (m *MockFileEditor) GetCmdExecutor(_ string, filename string) CommandExecutor {
	m.filename = filename
	return m
}
