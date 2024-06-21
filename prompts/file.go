package prompts

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/spectrocloud-labs/prompts-tui/prompts/mocks"
)

var (
	editorBinary   = "vi"
	editorPath     = ""
	GetCmdExecutor = getEditorExecutor
)

func init() {
	visual := os.Getenv("VISUAL")
	editor := os.Getenv("EDITOR")
	if visual != "" {
		editorBinary = visual
		logger.Info(fmt.Sprintf("Detected VISUAL env var. Overrode default editor (vi) with %s.", editorBinary))
	} else if editor != "" {
		editorBinary = editor
		logger.Info(fmt.Sprintf("Detected EDITOR env var. Overrode default editor (vi) with %s.", editorBinary))
	}
	var err error
	editorPath, err = exec.LookPath(editorBinary)
	if err != nil {
		logger.Info(fmt.Sprintf("Error: %s not found on PATH. Either install vi or export VISUAL or EDITOR to an editor of your choosing.", editorBinary))
		os.Exit(1)
	}
}

func getEditorExecutor(editor, filename string) mocks.CommandExecutor {
	cmd := exec.Command(editor, filename)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd
}

func EditFile(initialContent []byte) ([]byte, error) {
	tmpFile, err := os.CreateTemp(os.TempDir(), "validator")
	if err != nil {
		return nil, err
	}
	filename := tmpFile.Name()
	if err := tmpFile.Close(); err != nil {
		return nil, err
	}

	if initialContent != nil {
		if err := os.WriteFile(filename, initialContent, 0600); err != nil {
			return nil, err
		}
	}

	cmd := GetCmdExecutor(editorPath, filename)
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	if err := cmd.Wait(); err != nil {
		return nil, err
	}

	data, err := os.ReadFile(filename) //#nosec
	if err != nil {
		return nil, err
	}
	if err := os.Remove(filename); err != nil {
		return nil, err
	}
	return data, nil
}

// EditFileValidatedByLine prompts a user to edit a file with a predefined prompt, initial content, and separator.
// An optional line function can be specified to validate the content of each line.
// Entries within the file must be newline-separated. Additionally, a minimum number of entries can be specified.
// The values on each line are joined by the separator and returned to the caller.
func EditFileValidatedByLine(prompt, content, separator string, lineValidate func(input string) error, minEntries int) (string, error) {
	if separator == "" {
		return "", errors.New("a non-empty separator is required")
	}

	for {
		var partsBytes []byte
		if content != "" {
			parts := bytes.Split([]byte(content), []byte(separator))
			partsBytes = bytes.Join(parts, []byte("\n"))
		}

		partsBytes, err := EditFile(append([]byte(prompt), partsBytes...))
		if err != nil {
			return content, err
		}
		lines := strings.Split(string(partsBytes), "\n")

		finalLines, err := stripCommentsAndValidateLines(lines, lineValidate)
		if err != nil && errors.Is(err, ValidationError) {
			// for integration tests, return the error
			if os.Getenv("IS_TEST") == "true" {
				return "", err
			}
			// otherwise, we assume the validation function logged
			// a meaningful error message and let the user try again
			time.Sleep(5 * time.Second)
			continue
		}
		if minEntries > 0 && len(finalLines) < minEntries {
			logger.Info(fmt.Sprintf("Error editing file: %d or more entries are required", minEntries))
			time.Sleep(5 * time.Second)
			continue
		}

		content = strings.TrimRight(strings.Join(finalLines, separator), separator)
		return content, err
	}
}

// EditFileValidatedByFullContent prompts a user to edit a file with a predefined prompt and initial content.
// An optional file validation function can be specified to validate the content of the entire file.
// Additionally, a minimum number of lines can be specified for the file.
// The final file content is returned to the caller.
func EditFileValidatedByFullContent(prompt, content string, fileValidate func(content string) error, minLines int) (string, error) {
	for {
		partsBytes := []byte(content)
		partsBytes, err := EditFile(append([]byte(prompt), partsBytes...))
		if err != nil {
			return content, err
		}
		lines := strings.Split(string(partsBytes), "\n")

		finalLines, _ := stripCommentsAndValidateLines(lines, nil)
		//content := strings.TrimRight(strings.Join(finalLines, separator), separator)
		content := strings.Join(finalLines, "\n")
		if fileValidate != nil {
			if err = fileValidate(content); err != nil {
				// for integration tests, return the error
				if os.Getenv("IS_TEST") == "true" {
					return "", err
				}
				// otherwise, we assume the validation function logged
				// a meaningful error message and let the user try again
				time.Sleep(5 * time.Second)
				continue
			}
		}

		if minLines > 0 && len(finalLines) < minLines {
			logger.Info(fmt.Sprintf("Error editing file: %d or more lines are required", minLines))
			time.Sleep(5 * time.Second)
			continue
		}

		return content, err
	}
}

// parses lines of a file, skips comments and optionally validating each line
func stripCommentsAndValidateLines(lines []string, lineValidate func(input string) error) ([]string, error) {
	finalLines := make([]string, 0)

	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "#") {
			if lineValidate != nil {
				if err := lineValidate(l); err != nil {
					return finalLines, err
				}
			}
			finalLines = append(finalLines, l)
		}
	}

	return finalLines, nil
}
