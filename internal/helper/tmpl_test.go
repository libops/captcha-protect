package helper

import (
	"strings"
	"testing"
)

func TestGetDefaultTmpl(t *testing.T) {
	tmpl := GetDefaultTmpl()

	// Verify it returns a non-empty string
	if tmpl == "" {
		t.Error("GetDefaultTmpl returned empty string")
	}

	// Verify it contains expected HTML elements
	expectedElements := []string{
		"<html>",
		"</html>",
		"<head>",
		"</head>",
		"<body>",
		"</body>",
		"<form",
		"</form>",
		"{{ .FrontendJS }}",
		"{{ .SiteKey }}",
		"{{ .ChallengeURL }}",
		"{{ .Destination }}",
		"{{ .FrontendKey }}",
		"captchaCallback",
	}

	for _, elem := range expectedElements {
		if !strings.Contains(tmpl, elem) {
			t.Errorf("Template missing expected element: %s", elem)
		}
	}

	// Verify it's valid HTML structure (basic check)
	if !strings.HasPrefix(tmpl, "<html>") {
		t.Error("Template should start with <html>")
	}
	if !strings.HasSuffix(strings.TrimSpace(tmpl), "</html>") {
		t.Error("Template should end with </html>")
	}
}
