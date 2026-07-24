package relay

// RelayUpstreamTarget mirrors agent_bom.runtime.gateway_relay_contract.RelayUpstreamTarget.
type RelayUpstreamTarget struct {
	Name                    string `json:"name"`
	URL                     string `json:"url"`
	TenantID                string `json:"tenant_id"`
	PrivateNetworkApproved  bool   `json:"private_network_approved"`
}

// RelayForwardRequest mirrors RelayForwardRequest JSON.
type RelayForwardRequest struct {
	Upstream RelayUpstreamTarget  `json:"upstream"`
	Message  map[string]any       `json:"message"`
	Headers  map[string]string    `json:"headers"`
}

// RelayForwardResult mirrors RelayForwardResult JSON.
type RelayForwardResult struct {
	Message      map[string]any `json:"message"`
	UpstreamName string         `json:"upstream_name"`
	BytesRead    int            `json:"bytes_read"`
}

const MaxMessageBytes = 2 * 1024 * 1024
