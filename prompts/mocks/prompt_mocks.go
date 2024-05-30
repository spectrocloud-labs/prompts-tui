package mocks

import (
	"fmt"
	"strings"

	"golang.org/x/exp/slices"
)

type MockTUI struct {
	ReturnVals []string
	Errs       []error
	validate   func(string) error
}

func (m *MockTUI) GetBool(prompt string, defaultVal bool) (bool, error) {
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

func (m *MockTUI) GetText(prompt, defaultVal, mask string, optional bool, validate func(string) error) (string, error) {
	if validate != nil {
		m.validate = validate
	}
	return m.run()
}

func (m *MockTUI) GetSelection(prompt string, options []string) (string, error) {
	val, err := m.run()
	if err != nil {
		return val, err
	}
	if !slices.Contains(options, val) {
		return val, fmt.Errorf("GetSelection: input %s not found in options %s", val, options)
	}
	return val, nil
}

func (m *MockTUI) GetMultiSelection(prompt string, options []string, minSelections int) ([]string, error) {
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
	val, m.ReturnVals = m.ReturnVals[0], m.ReturnVals[1:]
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
