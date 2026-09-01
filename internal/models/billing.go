package models

import (
	"time"

	"github.com/google/uuid"
)

// UserSubscription represents cached user subscription and entitlements from astian-payment
type UserSubscription struct {
	UserID             uuid.UUID  `json:"user_id"`
	PlanID             *int64     `json:"plan_id,omitempty"`
	PlanSlug           string     `json:"plan_slug"`
	PlanName           string     `json:"plan_name"`
	StripeStatus       string     `json:"stripe_status"`
	IsActive           bool       `json:"is_active"`
	IsOnTrial          bool       `json:"is_on_trial"`
	IsOnGracePeriod    bool       `json:"is_on_grace_period"`
	MaxDevices         int        `json:"max_devices"`
	BandwidthLimitGB   int64      `json:"bandwidth_limit_gb"` // 0 = Unlimited
	SpeedLimitMbps     int        `json:"speed_limit_mbps"`   // 0 = Unlimited
	AllowedLocations   []string   `json:"allowed_locations"`
	AdblockEnabled     bool       `json:"adblock_enabled"`
	TrialEndsAt        *time.Time `json:"trial_ends_at,omitempty"`
	CurrentPeriodStart time.Time  `json:"current_period_start"`
	CurrentPeriodEnd   time.Time  `json:"current_period_end"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
}

// UserBandwidthUsage tracks historical monthly bandwidth consumption
type UserBandwidthUsage struct {
	ID              uuid.UUID `json:"id"`
	UserID          uuid.UUID `json:"user_id"`
	PeriodStart     time.Time `json:"period_start"`
	PeriodEnd       time.Time `json:"period_end"`
	BytesUploaded   int64     `json:"bytes_uploaded"`
	BytesDownloaded int64     `json:"bytes_downloaded"`
	TotalBytes      int64     `json:"total_bytes"`
	IsThrottled     bool      `json:"is_throttled"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// AstianEntitlementResponse represents the typed payload from astian-payment internal API
type AstianEntitlementResponse struct {
	UserID       int64                       `json:"user_id"`
	Email        string                      `json:"email"`
	Name         string                      `json:"name"`
	Entitlements []AstianSubscriptionPayload `json:"entitlements"`
}

type AstianSubscriptionPayload struct {
	SubscriptionID  int64                  `json:"subscription_id"`
	ServiceSlug     string                 `json:"service_slug"`
	StripeStatus    string                 `json:"stripe_status"`
	IsActive        bool                   `json:"is_active"`
	IsOnTrial       bool                   `json:"is_on_trial"`
	IsOnGracePeriod bool                   `json:"is_on_grace_period"`
	TrialEndsAt     *time.Time             `json:"trial_ends_at,omitempty"`
	EndsAt          *time.Time             `json:"ends_at,omitempty"`
	Plan            *AstianPlanPayload     `json:"plan,omitempty"`
	Entitlements    map[string]interface{} `json:"entitlements"`
}

type AstianPlanPayload struct {
	ID        int64    `json:"id"`
	Name      string   `json:"name"`
	Slug      string   `json:"slug"`
	Category  string   `json:"category"`
	Features  []string `json:"features"`
	MaxUsers  *int     `json:"max_users,omitempty"`
	StorageGB *int     `json:"storage_gb,omitempty"`
}
