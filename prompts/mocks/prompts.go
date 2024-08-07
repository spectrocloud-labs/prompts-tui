package mocks

import (
	"fmt"
	"strings"

	"golang.org/x/exp/slices"
)

// MockTUI is a mock implementation of the TUI interface for testing purposes.
type MockTUI struct {
	Values        []string
	SliceValues   [][]string
	Errs          []error
	validate      func(string) error
	validateSlice func([]string) error
}

// GetBool returns the next value in the Values slice as a bool.
func (m *MockTUI) GetBool(_ string, defaultVal bool) (bool, error) {
	val, err := m.run()
	if err != nil {
		return false, err
	}
	val = strings.ToLower(val)
	if !slices.Contains([]string{"", "y", "n"}, val) {
		return false, fmt.Errorf("GetBool: invalid input: %s", val)
	}
	if val == "" {
		return defaultVal, err
	}
	return val == "y", err
}

// GetText returns the next value in the Values slice as a string.
func (m *MockTUI) GetText(_, _, _ string, _ bool, validate func(string) error) (string, error) {
	if validate != nil {
		m.validate = validate
	}
	return m.run()
}

// GetTextSlice returns the next value in the SliceValues slice as a []string.
func (m *MockTUI) GetTextSlice(_, _ string, _ bool, validate func([]string) error) ([]string, error) {
	if validate != nil {
		m.validateSlice = validate
	}
	return m.runSlice()
}

// GetSelection returns the next value in the Values slice as a string.
func (m *MockTUI) GetSelection(_ string, options []string) (string, error) {
	val, err := m.run()
	if err != nil {
		return val, err
	}
	if !slices.Contains(options, val) {
		return val, fmt.Errorf("GetSelection: input %s not found in options %s", val, options)
	}
	return val, nil
}

// GetMultiSelection returns the next minSelections values in the Values slice as a []string.
func (m *MockTUI) GetMultiSelection(_ string, _ []string, minSelections int) ([]string, error) {
	vals := make([]string, 0)
	for i := 0; i < minSelections; i++ {
		val, err := m.run()
		if err != nil {
			return nil, err
		}
		vals = append(vals, val)
	}
	return vals, nil
}

func (m *MockTUI) run() (val string, err error) {
	val, m.Values = m.Values[0], m.Values[1:]
	if m.validate != nil {
		validateErr := m.validate(val)
		if validateErr != nil {
			m.Errs = []error{validateErr}
		}
		m.validate = nil // reset for subsequent prompts
	}
	if m.Errs != nil {
		err, m.Errs = m.Errs[0], m.Errs[1:]
	}
	return val, err
}

func (m *MockTUI) runSlice() (val []string, err error) {
	val, m.SliceValues = m.SliceValues[0], m.SliceValues[1:]
	if m.validateSlice != nil {
		validateErr := m.validateSlice(val)
		if validateErr != nil {
			m.Errs = []error{validateErr}
		}
		m.validateSlice = nil // reset for subsequent prompts
	}
	if m.Errs != nil {
		err, m.Errs = m.Errs[0], m.Errs[1:]
	}
	return val, err
}
