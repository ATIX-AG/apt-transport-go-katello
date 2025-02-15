package main

import (
  "fmt"
	"os"
	"testing"
)

// Mock function to replace os.Stdin for testing
func mockStdin(input string, f func()) {
	oldStdin := os.Stdin
	defer func() { os.Stdin = oldStdin }()

	r, w, _ := os.Pipe()
	if _, err := w.WriteString(input); err != nil {
		panic(fmt.Sprintf("Failed to write to pipe: %v", err))
	}
	w.Close()

	os.Stdin = r
	f()
}

// Test_getNextMsg tests the getNextMsg function.
func Test_getNextMsg(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		expected   map[string]string
		expectErr  bool
	}{
		{
			name:  "Valid message with headers",
			input: "102 Status\nFilename: test.rpm\nSize: 1024\n\n",
			expected: map[string]string{
				"_number":  "102",
				"_text":    "Status",
				"Filename": "test.rpm",
				"Size":     "1024",
			},
			expectErr: false,
		},
		{
			name:  "Valid message without headers",
			input: "200 URI Start\n\n",
			expected: map[string]string{
				"_number": "200",
				"_text":   "URI Start",
			},
			expectErr: false,
		},
		{
			name:  "Empty input (EOF case)",
			input: "",
			expected: nil,
			expectErr: true,
		},
		{
			name:  "Handles extra newlines before message",
			input: "\n\n\n102 Status\nFilename: file.iso\nSize: 500MB\n\n",
			expected: map[string]string{
				"_number":  "102",
				"_text":    "Status",
				"Filename": "file.iso",
				"Size":     "500MB",
			},
			expectErr: false,
		},
		{
			name:  "Handles missing values in headers",
			input: "201 URI Done\nFilename:\nSize: 4096\n\n",
			expected: map[string]string{
				"_number": "201",
				"_text":   "URI Done",
				"Size":    "4096",
			},
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Mock stdin with test input
			mockStdin(tt.input, func() {
				p := &pkgAcquireMethod{}
				result, err := p.getNextMsg()

				// Step 1: Check for expected error
				if (err != nil) != tt.expectErr {
					t.Errorf("getNextMsg() error = %v, wantErr %v", err, tt.expectErr)
					return
				}

				// Step 2: If error was expected, stop further checks
				if tt.expectErr {
					return
				}

				// Step 3: Validate parsed message content
				for key, expectedValue := range tt.expected {
					if result[key] != expectedValue {
						t.Errorf("getNextMsg()[%q] = %q, want %q", key, result[key], expectedValue)
					}
				}
			})
		})
	}
}

