package control

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/goastian/midori-vpn-core/internal/desiredstate"
	"github.com/goastian/midori-vpn-core/internal/models"
	"github.com/goastian/midori-vpn-core/internal/repo"
	"github.com/google/uuid"
)

type desiredStateRenewalStoreStub struct {
	candidates []models.DesiredRevision
	created    []*models.DesiredRevision
	listErr    error
	createErr  error
}

func (s *desiredStateRenewalStoreStub) ListDesiredRenewalCandidates(context.Context, time.Time, int) ([]models.DesiredRevision, error) {
	return s.candidates, s.listErr
}

func (s *desiredStateRenewalStoreStub) CreateDesiredRevision(_ context.Context, revision *models.DesiredRevision) error {
	if s.createErr != nil {
		return s.createErr
	}
	copyRevision := *revision
	copyRevision.Payload = bytes.Clone(revision.Payload)
	copyRevision.PayloadSHA256 = bytes.Clone(revision.PayloadSHA256)
	copyRevision.Signature = bytes.Clone(revision.Signature)
	s.created = append(s.created, &copyRevision)
	return nil
}

func TestDesiredStateRenewerReissuesVerifiedExpiredLease(t *testing.T) {
	now := time.Date(2026, time.September, 5, 18, 0, 0, 0, time.UTC)
	signer, verifier := desiredStateRenewalSigner(t)
	source := desiredStateRenewalFixture(t, signer, now.Add(-25*time.Hour), now.Add(-time.Hour))
	originalPayload := bytes.Clone(source.Payload)
	store := &desiredStateRenewalStoreStub{candidates: []models.DesiredRevision{source}}
	renewer := &DesiredStateRenewer{store: store, signer: signer, verifier: verifier}

	report := renewer.RunOnce(context.Background(), now)
	if report.Candidates != 1 || report.Renewed != 1 || report.Conflicts != 0 || report.Errors != 0 {
		t.Fatalf("renewal report = %#v", report)
	}
	if len(store.created) != 1 {
		t.Fatalf("created revisions = %d, want 1", len(store.created))
	}
	created := store.created[0]
	if created.Revision != 2 || created.PreviousRevision == nil || *created.PreviousRevision != 1 {
		t.Fatalf("renewed chain = revision %d previous %v", created.Revision, created.PreviousRevision)
	}
	if !created.IssuedAt.Equal(now) || !created.ExpiresAt.Equal(now.Add(desiredStateLeaseDuration)) {
		t.Fatalf("renewed lease = %s..%s", created.IssuedAt, created.ExpiresAt)
	}
	if !bytes.Equal(source.Payload, originalPayload) {
		t.Fatal("historical desired-state payload was mutated")
	}
	signed, err := desiredstate.DecodeStored(created.Payload, created.PayloadSHA256, created.Signature, created.SigningKeyID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(signed, source.NodeID, "2.0.0", now, false); err != nil {
		t.Fatalf("renewed signature failed verification: %v", err)
	}
	if signed.Bundle.ManagementEndpoint != "https://control.example.test" || signed.Bundle.Capacity.MaxPeers != 100 {
		t.Fatalf("renewal changed desired intent: %#v", signed.Bundle)
	}
}

func TestDesiredStateRenewerRejectsInvalidStoredSignature(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	signer, verifier := desiredStateRenewalSigner(t)
	source := desiredStateRenewalFixture(t, signer, now.Add(-time.Hour), now.Add(time.Minute))
	source.Signature[0] ^= 0xff
	store := &desiredStateRenewalStoreStub{candidates: []models.DesiredRevision{source}}
	report := (&DesiredStateRenewer{store: store, signer: signer, verifier: verifier}).RunOnce(context.Background(), now)
	if report.Errors != 1 || report.Renewed != 0 || len(store.created) != 0 {
		t.Fatalf("invalid signature renewal report = %#v created=%d", report, len(store.created))
	}
}

func TestDesiredStateRenewerTreatsConcurrentRevisionAsConflict(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	signer, verifier := desiredStateRenewalSigner(t)
	store := &desiredStateRenewalStoreStub{
		candidates: []models.DesiredRevision{desiredStateRenewalFixture(t, signer, now.Add(-time.Hour), now.Add(time.Minute))},
		createErr:  repo.ErrDesiredRevisionConflict,
	}
	report := (&DesiredStateRenewer{store: store, signer: signer, verifier: verifier}).RunOnce(context.Background(), now)
	if report.Conflicts != 1 || report.Errors != 0 || report.Renewed != 0 {
		t.Fatalf("concurrent renewal report = %#v", report)
	}
}

func TestDesiredStateRenewerReportsCandidateLookupFailure(t *testing.T) {
	signer, verifier := desiredStateRenewalSigner(t)
	store := &desiredStateRenewalStoreStub{listErr: errors.New("database unavailable")}
	report := (&DesiredStateRenewer{store: store, signer: signer, verifier: verifier}).RunOnce(context.Background(), time.Now())
	if report.Errors != 1 || report.Candidates != 0 {
		t.Fatalf("lookup failure report = %#v", report)
	}
}

func desiredStateRenewalSigner(t *testing.T) (*desiredstate.Signer, *desiredstate.Verifier) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const keyID = "control-renewal-test"
	signer, err := desiredstate.NewSigner(keyID, base64.RawURLEncoding.EncodeToString(privateKey))
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := desiredstate.NewVerifier(keyID + "=" + base64.RawURLEncoding.EncodeToString(publicKey))
	if err != nil {
		t.Fatal(err)
	}
	return signer, verifier
}

func desiredStateRenewalFixture(t *testing.T, signer *desiredstate.Signer, issuedAt, expiresAt time.Time) models.DesiredRevision {
	t.Helper()
	bundle := desiredstate.Bundle{
		SchemaVersion: desiredstate.SchemaVersion,
		ClusterID:     uuid.MustParse("44444444-4444-4444-8444-444444444444"),
		NodeID:        uuid.MustParse("33333333-3333-4333-8333-333333333333"),
		Revision:      1, IssuedAt: issuedAt, ExpiresAt: expiresAt,
		MinimumCoreVersion: "2.0.0", ManagementEndpoint: "https://control.example.test",
		PublicEndpoints:  []desiredstate.PublicEndpoint{{Name: "wg", Host: "vpn.example.test", Port: 51820}},
		Capacity:         desiredstate.Capacity{MaxPeers: 100},
		Transports:       []desiredstate.Transport{{Protocol: "wireguard", Enabled: true, Priority: 10, Endpoint: "wg"}},
		SecretReferences: []desiredstate.SecretReference{},
	}
	signed, payload, digest, err := signer.Sign(bundle)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := base64.RawURLEncoding.DecodeString(signed.Signature)
	if err != nil {
		t.Fatal(err)
	}
	return models.DesiredRevision{
		NodeID: bundle.NodeID, Revision: 1, SchemaVersion: bundle.SchemaVersion,
		MinimumCoreVersion: bundle.MinimumCoreVersion, Payload: payload,
		PayloadSHA256: digest, Signature: signature, SigningKeyID: signed.SigningKeyID,
		IssuedAt: issuedAt, ExpiresAt: expiresAt,
	}
}
