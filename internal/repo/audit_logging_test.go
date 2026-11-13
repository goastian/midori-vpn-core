package repo

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

type invalidAuditMetadata struct{}

func (invalidAuditMetadata) MarshalJSON() ([]byte, error) {
	return nil, errors.New("private-metadata-value")
}

func TestAuditRejectsUnencodableMetadata(t *testing.T) {
	// Encoding must fail before reaching the database, not persist an empty
	// event that hides the loss of its metadata.
	if err := NewAuditRepo(nil).Log(context.Background(), nil, "test.action", map[string]interface{}{"value": invalidAuditMetadata{}}, "private-ip"); err == nil {
		t.Fatal("unencodable audit metadata was silently discarded")
	}
}

func TestBestEffortAuditFailureIsObservableWithoutPrivateDetails(t *testing.T) {
	var output bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&output, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	NewAuditRepo(nil).LogBestEffort(context.Background(), nil, "test.action", map[string]interface{}{"value": invalidAuditMetadata{}}, "private-ip")
	text := output.String()
	if !strings.Contains(text, `"level":"WARN"`) || !strings.Contains(text, `"action":"test.action"`) {
		t.Fatalf("failure not observable: %s", text)
	}
	if strings.Contains(text, "private-metadata-value") || strings.Contains(text, "private-ip") {
		t.Fatalf("private audit data leaked: %s", text)
	}
}
