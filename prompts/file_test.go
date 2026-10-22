package prompts

import (
	"os/exec"
	"testing"
)

// Covers PLT-2471: EDITOR/VISUAL values containing arguments (e.g. "code -w") must have
// those arguments passed through to the spawned editor command, not treated as part of
// the binary name.
func TestGetEditorExecutorPassesEditorArgs(t *testing.T) {
	origArgs := editorArgs
	defer func() { editorArgs = origArgs }()

	editorArgs = []string{"-w", "--foo"}
	cmd, ok := getEditorExecutor("/usr/bin/code", "/tmp/somefile.txt").(*exec.Cmd)
	if !ok {
		t.Fatalf("expected *exec.Cmd, got %T", cmd)
	}

	want := []string{"/usr/bin/code", "-w", "--foo", "/tmp/somefile.txt"}
	if len(cmd.Args) != len(want) {
		t.Fatalf("got args %v, want %v", cmd.Args, want)
	}
	for i, w := range want {
		if cmd.Args[i] != w {
			t.Fatalf("arg %d: got %q, want %q (full args: %v)", i, cmd.Args[i], w, cmd.Args)
		}
	}
}

func TestGetEditorExecutorNoEditorArgs(t *testing.T) {
	origArgs := editorArgs
	defer func() { editorArgs = origArgs }()

	editorArgs = nil
	cmd, ok := getEditorExecutor("/usr/bin/vi", "/tmp/somefile.txt").(*exec.Cmd)
	if !ok {
		t.Fatalf("expected *exec.Cmd, got %T", cmd)
	}

	want := []string{"/usr/bin/vi", "/tmp/somefile.txt"}
	if len(cmd.Args) != len(want) {
		t.Fatalf("got args %v, want %v", cmd.Args, want)
	}
	for i, w := range want {
		if cmd.Args[i] != w {
			t.Fatalf("arg %d: got %q, want %q (full args: %v)", i, cmd.Args[i], w, cmd.Args)
		}
	}
}
