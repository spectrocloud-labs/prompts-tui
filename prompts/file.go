package prompts

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/pterm/pterm"
	"github.com/spectrocloud-labs/prompts-tui/prompts/mocks"
)

var (
	editorBinary = "vi"
	editorPath   = ""

	// GetCmdExecutor allows monkey-patching the command executor for testing purposes.
	GetCmdExecutor = getEditorExecutor
)

func init() {
	visual := os.Getenv("VISUAL")
	editor := os.Getenv("EDITOR")
	if visual != "" {
		editorBinary = visual
		logger.Debug(fmt.Sprintf("Detected VISUAL env var. Overrode default editor (vi) with %s.", editorBinary))
	} else if editor != "" {
		editorBinary = editor
		logger.Debug(fmt.Sprintf("Detected EDITOR env var. Overrode default editor (vi) with %s.", editorBinary))
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

// EditFile prompts a user to edit a file with a predefined prompt and initial content.
func EditFile(initialContent []byte) ([]byte, error) {
	tmpFile, err := os.CreateTemp(os.TempDir(), "prompts")
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

		finalLines, err := FilterLines(lines, lineValidate)
		if err != nil && errors.Is(err, ErrValidationFailed) {
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

		finalLines, _ := FilterLines(lines, nil)
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

// FilterLines filters a list of lines from a file. Comment lines (starting with '#') and
// any line matching an optional validation function are removed.
func FilterLines(lines []string, validate func(input string) error) ([]string, error) {
	out := make([]string, 0)

	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "#") {
			if validate != nil {
				if err := validate(l); err != nil {
					return out, err
				}
			}
			out = append(out, l)
		}
	}

	return out, nil
}

// RemoveFile prompts a user whether they want to remove a file. Removes the file if the user wants
// it to be removed. If no error is encountered, prints a message telling the user the result. In
// case of error, does not print any further message and returns the error to be handled by caller.
func RemoveFile(path string, defaultVal bool) error {
	remove, err := ReadBool(fmt.Sprintf("Remove file %s from disk", path), defaultVal)
	if err != nil {
		return err
	}

	if remove {
		if err := os.Remove(path); err != nil {
			return err
		}
		pterm.Info.Println("File removed.")
	} else {
		pterm.Info.Println("File kept.")
	}

	return nil
}
