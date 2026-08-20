package control

import (
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/goastian/midori-vpn-core/internal/auth"
	"github.com/goastian/midori-vpn-core/internal/respond"
)

// ExportIKEv2MobileConfig generates an Apple-compatible .mobileconfig profile
// for native iOS / macOS IKEv2 / IPsec VPN integration.
func (h *Handler) ExportIKEv2MobileConfig(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUser(r)
	if user == nil {
		respond.JsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	serverIDStr := chi.URLParam(r, "id")
	serverID, err := uuid.Parse(serverIDStr)
	if err != nil {
		respond.JsonError(w, "invalid server id", http.StatusBadRequest)
		return
	}

	server, err := h.serverRepo.GetByID(r.Context(), serverID)
	if err != nil {
		respond.JsonError(w, "server not found", http.StatusNotFound)
		return
	}

	host := server.Endpoint
	if host == "" {
		host = server.Host
	}

	profileUUID := uuid.New().String()
	payloadUUID := uuid.New().String()

	// Apple .mobileconfig XML template for IKEv2 VPN
	mobileconfig := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadDisplayName</key>
	<string>MidoriVPN - %s</string>
	<key>PayloadIdentifier</key>
	<string>org.astian.midorivpn.%s</string>
	<key>PayloadRemovalDisallowed</key>
	<false/>
	<key>PayloadType</key>
	<string>Configuration</string>
	<key>PayloadUUID</key>
	<string>%s</string>
	<key>PayloadVersion</key>
	<integer>1</integer>
	<key>PayloadContent</key>
	<array>
		<dict>
			<key>PayloadDisplayName</key>
			<string>MidoriVPN IKEv2</string>
			<key>PayloadIdentifier</key>
			<string>org.astian.midorivpn.ikev2.%s</string>
			<key>PayloadType</key>
			<string>com.apple.vpn.managed</string>
			<key>PayloadUUID</key>
			<string>%s</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
			<key>UserDefinedName</key>
			<string>MidoriVPN (%s)</string>
			<key>VPNType</key>
			<string>IKEv2</string>
			<key>IKEv2</key>
			<dict>
				<key>RemoteAddress</key>
				<string>%s</string>
				<key>RemoteIdentifier</key>
				<string>%s</string>
				<key>LocalIdentifier</key>
				<string>%s</string>
				<key>AuthenticationMethod</key>
				<string>None</string>
				<key>ExtendedAuthEnabled</key>
				<integer>1</integer>
				<key>AuthName</key>
				<string>%s</string>
				<key>DeadPeerDetectionRate</key>
				<string>Medium</string>
				<key>DisableMOBIKE</key>
				<integer>0</integer>
				<key>DisableRedirect</key>
				<integer>0</integer>
				<key>EnablePFS</key>
				<integer>1</integer>
				<key>IKESecurityAssociationParameters</key>
				<dict>
					<key>EncryptionAlgorithm</key>
					<string>AES-256-GCM</string>
					<key>IntegrityAlgorithm</key>
					<string>SHA2-384</string>
					<key>DiffieHellmanGroup</key>
					<integer>19</integer>
					<key>LifeTimeInMinutes</key>
					<integer>1440</integer>
				</dict>
				<key>ChildSecurityAssociationParameters</key>
				<dict>
					<key>EncryptionAlgorithm</key>
					<string>AES-256-GCM</string>
					<key>IntegrityAlgorithm</key>
					<string>SHA2-384</string>
					<key>DiffieHellmanGroup</key>
					<integer>19</integer>
					<key>LifeTimeInMinutes</key>
					<integer>1440</integer>
				</dict>
			</dict>
		</dict>
	</array>
</dict>
</plist>`, server.Name, profileUUID, profileUUID, payloadUUID, payloadUUID, server.Location, host, host, user.Email, user.Email)

	w.Header().Set("Content-Type", "application/x-apple-aspen-config")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="midorivpn-%s.mobileconfig"`, sanitizeDeviceName(server.Name)))
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(mobileconfig))
}
