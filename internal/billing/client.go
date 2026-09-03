package billing

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/goastian/midori-vpn-core/internal/config"
	"github.com/goastian/midori-vpn-core/internal/httpx"
	"github.com/goastian/midori-vpn-core/internal/models"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

const (
	entitlementsCacheTTL = 15 * time.Minute
	redisKeyPrefix       = "billing:entitlements:"
)

type Client struct {
	cfg        *config.Config
	httpClient *http.Client
	redis      *redis.Client
}

func NewClient(cfg *config.Config, rdb *redis.Client) *Client {
	return &Client{
		cfg:        cfg,
		httpClient: httpx.NewClient(1200 * time.Millisecond),
		redis:      rdb,
	}
}

// GetUserSubscription retrieves active plan, quota and entitlements for a user.
// Checks Redis cache first; falls back to astian-payment internal API or Default Free Plan.
func (c *Client) GetUserSubscription(ctx context.Context, userID uuid.UUID, authentikUID string) (*models.UserSubscription, error) {
	cacheKey := fmt.Sprintf("%s%s", redisKeyPrefix, userID.String())

	// 1. Try Redis cache
	if c.redis != nil {
		val, err := c.redis.Get(ctx, cacheKey).Result()
		if err == nil && val != "" {
			var sub models.UserSubscription
			if err := json.Unmarshal([]byte(val), &sub); err == nil {
				return &sub, nil
			}
		}
	}

	// 2. Fetch from astian-payment API if configured
	sub, err := c.fetchFromAstianPayment(ctx, userID, authentikUID)
	if err != nil {
		slog.Warn("Failed to fetch entitlements from astian-payment; applying default free plan",
			"user_id", userID, "error", err)
		sub = c.defaultFreePlan(userID)
	}

	// 3. Populate Redis cache
	if c.redis != nil && sub != nil {
		if data, err := json.Marshal(sub); err == nil {
			bgCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = c.redis.Set(bgCtx, cacheKey, data, entitlementsCacheTTL).Err()
		}
	}

	return sub, nil
}

// InvalidateCache clears the Redis cache for a user upon webhook notification.
func (c *Client) InvalidateCache(ctx context.Context, userID uuid.UUID) error {
	if c.redis == nil {
		return nil
	}
	cacheKey := fmt.Sprintf("%s%s", redisKeyPrefix, userID.String())
	return c.redis.Del(ctx, cacheKey).Err()
}

func (c *Client) fetchFromAstianPayment(ctx context.Context, userID uuid.UUID, authentikUID string) (*models.UserSubscription, error) {
	if c.cfg.AstianPaymentURL == "" {
		return nil, fmt.Errorf("astian-payment URL not configured")
	}

	// Astian Payment Internal API endpoint
	apiURL := fmt.Sprintf("%s/api/internal/v1/users/%s/entitlements?service_slug=midori-vpn",
		c.cfg.AstianPaymentURL, authentikUID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/json")
	if c.cfg.AstianPaymentToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.cfg.AstianPaymentToken)
		req.Header.Set("X-Service-Token", c.cfg.AstianPaymentToken)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return c.defaultFreePlan(userID), nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("astian-payment returned status %d", resp.StatusCode)
	}

	body, err := httpx.ReadBody(resp.Body, httpx.MaxResponseBytes)
	if err != nil {
		code := "response_read_failed"
		responseBytes := 0
		if errors.Is(err, httpx.ErrResponseTooLarge) {
			code = "response_too_large"
			responseBytes = httpx.MaxResponseBytes + 1
		}
		return nil, httpx.NewRemoteError("astian_payment_entitlements", code, resp.StatusCode, responseBytes, err)
	}
	var payload models.AstianEntitlementResponse
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, httpx.NewRemoteError("astian_payment_entitlements", "response_invalid", resp.StatusCode, len(body), err)
	}

	return c.mapPayloadToSubscription(userID, &payload), nil
}

func (c *Client) mapPayloadToSubscription(userID uuid.UUID, payload *models.AstianEntitlementResponse) *models.UserSubscription {
	sub := c.defaultFreePlan(userID)

	if len(payload.Entitlements) == 0 {
		return sub
	}

	activeSub := payload.Entitlements[0]
	sub.IsActive = activeSub.IsActive
	sub.IsOnTrial = activeSub.IsOnTrial
	sub.IsOnGracePeriod = activeSub.IsOnGracePeriod
	sub.StripeStatus = activeSub.StripeStatus
	sub.TrialEndsAt = activeSub.TrialEndsAt

	if activeSub.Plan != nil {
		sub.PlanID = &activeSub.Plan.ID
		sub.PlanSlug = activeSub.Plan.Slug
		sub.PlanName = activeSub.Plan.Name
	}

	// Parse Typed Entitlements
	if devices, ok := activeSub.Entitlements["midori-vpn.devices_max"]; ok {
		sub.MaxDevices = toInt(devices, sub.MaxDevices)
	}
	if bw, ok := activeSub.Entitlements["midori-vpn.bandwidth_gb"]; ok {
		sub.BandwidthLimitGB = int64(toInt(bw, int(sub.BandwidthLimitGB)))
	}
	if speed, ok := activeSub.Entitlements["midori-vpn.speed_limit_mbps"]; ok {
		sub.SpeedLimitMbps = toInt(speed, sub.SpeedLimitMbps)
	}
	if adblock, ok := activeSub.Entitlements["midori-vpn.adblock"]; ok {
		if b, ok := adblock.(bool); ok {
			sub.AdblockEnabled = b
		}
	}

	sub.UpdatedAt = time.Now()
	return sub
}

func (c *Client) defaultFreePlan(userID uuid.UUID) *models.UserSubscription {
	now := time.Now()
	return &models.UserSubscription{
		UserID:             userID,
		PlanSlug:           "free",
		PlanName:           "Free Plan",
		StripeStatus:       "active",
		IsActive:           true,
		IsOnTrial:          false,
		IsOnGracePeriod:    false,
		MaxDevices:         1,
		BandwidthLimitGB:   10, // 10 GB Free Monthly
		SpeedLimitMbps:     0,  // Unlimited Nominal
		AllowedLocations:   []string{"DO", "US"},
		AdblockEnabled:     false,
		CurrentPeriodStart: now,
		CurrentPeriodEnd:   now.AddDate(0, 1, 0),
		CreatedAt:          now,
		UpdatedAt:          now,
	}
}

func toInt(v interface{}, fallback int) int {
	switch val := v.(type) {
	case int:
		return val
	case float64:
		return int(val)
	case string:
		if n, err := strconv.Atoi(val); err == nil {
			return n
		}
	}
	return fallback
}
