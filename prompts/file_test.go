package prompts

import (
	"reflect"
	"testing"
)

func TestSplitEditorCommand(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    []string
		wantErr bool
	}{
		{
			name: "bare command",
			in:   "vi",
			want: []string{"vi"},
		},
		{
			name: "command with a flag",
			in:   "code -w",
			want: []string{"code", "-w"},
		},
		{
			name: "command with multiple flags",
			in:   "code --wait --new-window",
			want: []string{"code", "--wait", "--new-window"},
		},
		{
			name: "quoted path with spaces plus a flag",
			in:   `"/Applications/Visual Studio Code.app/Contents/MacOS/Electron" -w`,
			want: []string{"/Applications/Visual Studio Code.app/Contents/MacOS/Electron", "-w"},
		},
		{
			name: "single-quoted path with spaces",
			in:   `'/path with spaces/bin/edit' -w`,
			want: []string{"/path with spaces/bin/edit", "-w"},
		},
		{
			name: "quoted argument preserves embedded spaces",
			in:   `vim -c "set nu"`,
			want: []string{"vim", "-c", "set nu"},
		},
		{
			name: "backslash escapes a space",
			in:   `/path/with\ space/bin -w`,
			want: []string{"/path/with space/bin", "-w"},
		},
		{
			name: "leading and trailing whitespace is trimmed",
			in:   "  code  -w  ",
			want: []string{"code", "-w"},
		},
		{
			name: "empty value yields no fields",
			in:   "",
			want: nil,
		},
		{
			name: "whitespace-only value yields no fields",
			in:   "   ",
			want: nil,
		},
		{
			name:    "unterminated double quote is an error",
			in:      `"code -w`,
			wantErr: true,
		},
		{
			name:    "unterminated single quote is an error",
			in:      `'code -w`,
			wantErr: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := splitEditorCommand(c.in)
			if c.wantErr {
				if err == nil {
					t.Fatalf("splitEditorCommand(%q) expected an error, got %v", c.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("splitEditorCommand(%q) unexpected error: %v", c.in, err)
			}
			if len(got) == 0 {
				got = nil
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("splitEditorCommand(%q) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}
