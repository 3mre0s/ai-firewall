package patterns

import (
	"testing"
)

func TestPatternsRegistry(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		targetType  PatternType
		input       string
		shouldMatch bool
		expectedVal string // expected capture group (if GroupIndex > 0) or full match
	}{
		{
			name:        "GitHub PAT Match",
			targetType:  TypeToken,
			input:       "ghp_123456789012345678901234567890123456",
			shouldMatch: true,
			expectedVal: "ghp_123456789012345678901234567890123456",
		},
		{
			name:        "AWS Access Key Match",
			targetType:  TypeKey,
			input:       "AKIAIOSFODNN7EXAMPLE",
			shouldMatch: true,
			expectedVal: "AKIAIOSFODNN7EXAMPLE",
		},
		{
			name:        "HTTP Bearer Token Match",
			targetType:  TypeToken,
			input:       "Bearer my_super_secret_bearer_token",
			shouldMatch: true,
			expectedVal: "my_super_secret_bearer_token",
		},
		{
			name:        "Inline Secret Assignment Match",
			targetType:  TypeSecret,
			input:       "api_key: \"sk-1234567890\"",
			shouldMatch: true,
			expectedVal: "sk-1234567890",
		},
		{
			name:        "Unix Path Match",
			targetType:  TypePath,
			input:       "file is located at /home/user/secrets.txt",
			shouldMatch: true,
			expectedVal: "/home/user/secrets.txt",
		},
		{
			name:        "Windows Path Match",
			targetType:  TypePath,
			input:       `C:\Users\alice\Documents\secret.json`,
			shouldMatch: true,
			expectedVal: `C:\Users\alice\Documents\secret.json`,
		},
		{
			name:        "Email Address Match",
			targetType:  TypePII,
			input:       "contact support@example.com",
			shouldMatch: true,
			expectedVal: "support@example.com",
		},
		{
			name:        "OpenAI API Key Match",
			targetType:  TypeToken,
			input:       "sk-1234567890abcdef12345",
			shouldMatch: true,
			expectedVal: "sk-1234567890abcdef12345",
		},
		{
			name:        "OpenAI Project Key Match",
			targetType:  TypeToken,
			input:       "sk-proj-1234567890abcdef12345",
			shouldMatch: true,
			expectedVal: "sk-proj-1234567890abcdef12345",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			matched := false
			var foundVal string

			for _, pattern := range Registry {
				if pattern.Type != tc.targetType {
					continue
				}

				locs := pattern.Regex.FindStringSubmatchIndex(tc.input)
				if locs != nil {
					matched = true
					if pattern.GroupIndex > 0 && len(locs) >= (pattern.GroupIndex+1)*2 {
						start := locs[pattern.GroupIndex*2]
						end := locs[pattern.GroupIndex*2+1]
						foundVal = tc.input[start:end]
					} else {
						foundVal = tc.input[locs[0]:locs[1]]
					}
					break
				}
			}

			if matched != tc.shouldMatch {
				t.Errorf("expected match = %v, got %v for input %q", tc.shouldMatch, matched, tc.input)
			}

			if matched && foundVal != tc.expectedVal {
				t.Errorf("expected captured value %q, got %q", tc.expectedVal, foundVal)
			}
		})
	}
}
