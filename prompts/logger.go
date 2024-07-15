package prompts

import "github.com/pterm/pterm"

var logger = pterm.DefaultLogger

// SetLogger sets the logger to be used by the prompts package.
func SetLogger(l pterm.Logger) {
	logger = l
}
