package control

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/goastian/midori-vpn-core/internal/config"
	"github.com/goastian/midori-vpn-core/internal/desiredstate"
	"github.com/goastian/midori-vpn-core/internal/models"
	"github.com/goastian/midori-vpn-core/internal/repo"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	desiredStateLeaseDuration = 24 * time.Hour
	desiredStateRenewBefore   = 6 * time.Hour
	desiredStateRenewInterval = 5 * time.Minute
	desiredStateRenewTimeout  = 30 * time.Second
	desiredStateRenewBatch    = 128
)

type desiredStateRenewalStore interface {
	ListDesiredRenewalCandidates(context.Context, time.Time, int) ([]models.DesiredRevision, error)
	CreateDesiredRevision(context.Context, *models.DesiredRevision) error
}

type DesiredStateRenewalReport struct {
	Candidates int
	Renewed    int
	Conflicts  int
	Errors     int
}

type DesiredStateRenewer struct {
	store    desiredStateRenewalStore
	audit    *repo.AuditRepo
	signer   *desiredstate.Signer
	verifier *desiredstate.Verifier
}

var (
	desiredStateRenewalsTotal atomic.Uint64
	desiredStateRenewalErrors atomic.Uint64
)

func NewDesiredStateRenewer(pool *pgxpool.Pool, cfg *config.Config) (*DesiredStateRenewer, error) {
	if pool == nil || cfg == nil {
		return nil, errors.New("desired state renewal requires database and configuration")
	}
	signer, err := desiredstate.NewSigner(cfg.ControlNodeID, cfg.ControlNodePrivateKey)
	if err != nil {
		return nil, fmt.Errorf("initialize desired state renewal signer: %w", err)
	}
	verifier, err := desiredstate.NewVerifier(cfg.NodeAuthorizedKeys)
	if err != nil {
		return nil, fmt.Errorf("initialize desired state renewal verifier: %w", err)
	}
	if !verifier.Trusts(cfg.ControlNodeID, signer.PublicKey()) {
		return nil, errors.New("desired state renewal signer is not trusted")
	}
	return &DesiredStateRenewer{
		store: repo.NewMulticlusterRepo(pool), audit: repo.NewAuditRepo(pool),
		signer: signer, verifier: verifier,
	}, nil
}

func (r *DesiredStateRenewer) RunOnce(ctx context.Context, now time.Time) DesiredStateRenewalReport {
	report := DesiredStateRenewalReport{}
	if r == nil || r.store == nil || r.signer == nil || r.verifier == nil {
		report.Errors = 1
		desiredStateRenewalErrors.Add(1)
		return report
	}
	now = now.UTC().Truncate(time.Second)
	candidates, err := r.store.ListDesiredRenewalCandidates(ctx, now.Add(desiredStateRenewBefore), desiredStateRenewBatch)
	if err != nil {
		report.Errors = 1
		desiredStateRenewalErrors.Add(1)
		slog.Error("desired state renewal candidate lookup failed", "error", err)
		return report
	}
	report.Candidates = len(candidates)
	for index := range candidates {
		if err := r.renew(ctx, &candidates[index], now); err != nil {
			if errors.Is(err, repo.ErrDesiredRevisionConflict) {
				report.Conflicts++
				continue
			}
			report.Errors++
			desiredStateRenewalErrors.Add(1)
			slog.Error("desired state renewal failed",
				"node_id", candidates[index].NodeID,
				"revision", candidates[index].Revision,
				"error", err)
			continue
		}
		report.Renewed++
		desiredStateRenewalsTotal.Add(1)
	}
	return report
}

func (r *DesiredStateRenewer) renew(ctx context.Context, source *models.DesiredRevision, now time.Time) error {
	signed, err := desiredstate.DecodeStored(source.Payload, source.PayloadSHA256, source.Signature, source.SigningKeyID)
	if err != nil {
		return fmt.Errorf("decode stored desired state: %w", err)
	}
	if signed.Bundle.NodeID != source.NodeID || signed.Bundle.Revision != source.Revision {
		return errors.New("stored desired state identity does not match its row")
	}
	if _, err := r.verifier.Verify(signed, source.NodeID, signed.Bundle.MinimumCoreVersion, now, true); err != nil {
		return fmt.Errorf("verify stored desired state: %w", err)
	}

	previous := source.Revision
	bundle := signed.Bundle
	bundle.Revision = previous + 1
	bundle.PreviousRevision = &previous
	bundle.IssuedAt = now
	bundle.ExpiresAt = now.Add(desiredStateLeaseDuration)
	renewed, payload, digest, err := r.signer.Sign(bundle)
	if err != nil {
		return fmt.Errorf("sign renewed desired state: %w", err)
	}
	signature, err := base64.RawURLEncoding.DecodeString(renewed.Signature)
	if err != nil {
		return fmt.Errorf("decode renewed desired state signature: %w", err)
	}
	revision := &models.DesiredRevision{
		NodeID: source.NodeID, Revision: renewed.Bundle.Revision,
		PreviousRevision:   renewed.Bundle.PreviousRevision,
		SchemaVersion:      renewed.Bundle.SchemaVersion,
		MinimumCoreVersion: renewed.Bundle.MinimumCoreVersion,
		Payload:            payload, PayloadSHA256: digest, Signature: signature,
		SigningKeyID: renewed.SigningKeyID,
		IssuedAt:     renewed.Bundle.IssuedAt, ExpiresAt: renewed.Bundle.ExpiresAt,
	}
	if err := r.store.CreateDesiredRevision(ctx, revision); err != nil {
		return err
	}
	if r.audit != nil {
		if err := r.audit.Log(ctx, nil, "system.core-node.desired-state.renew", map[string]interface{}{
			"node_id": source.NodeID, "revision": revision.Revision,
			"previous_revision": previous,
		}, "system"); err != nil {
			slog.Error("desired state renewal audit failed", "node_id", source.NodeID, "revision", revision.Revision, "error", err)
		}
	}
	slog.Info("desired state renewed", "node_id", source.NodeID, "revision", revision.Revision, "expires_at", revision.ExpiresAt)
	return nil
}

func StartDesiredStateRenewal(parentCtx context.Context, pool *pgxpool.Pool, cfg *config.Config) {
	renewer, err := NewDesiredStateRenewer(pool, cfg)
	if err != nil {
		desiredStateRenewalErrors.Add(1)
		slog.Error("desired state renewal unavailable", "error", err)
		return
	}
	slog.Info("job started", "job", "desired-state-renewal", "interval", desiredStateRenewInterval.String(), "lease", desiredStateLeaseDuration.String())
	ticker := time.NewTicker(desiredStateRenewInterval)
	defer ticker.Stop()
	for {
		ctx, cancel := context.WithTimeout(parentCtx, desiredStateRenewTimeout)
		report := renewer.RunOnce(ctx, time.Now())
		cancel()
		slog.Info("desired state renewal completed",
			"candidates", report.Candidates, "renewed", report.Renewed,
			"conflicts", report.Conflicts, "errors", report.Errors)
		select {
		case <-parentCtx.Done():
			slog.Info("job stopped", "job", "desired-state-renewal")
			return
		case <-ticker.C:
		}
	}
}

func DesiredStateRenewalMetricsSnapshot() (uint64, uint64) {
	return desiredStateRenewalsTotal.Load(), desiredStateRenewalErrors.Load()
}
