// Package normalize turns EventBridge/CloudTrail envelopes into CloudChangeEvent JSON.
package normalize

import (
	"encoding/json"
	"fmt"
	"strings"
)

// CloudTrailDetailType is the EventBridge detail-type for CloudTrail API calls.
const CloudTrailDetailType = "AWS API Call via CloudTrail"

// resource types with posture rules in the Python control plane (parity subset).
var supportedResourceTypes = map[string]struct{}{
	"s3":         {},
	"ec2":        {},
	"iam":        {},
	"rds":        {},
	"kms":        {},
	"cloudtrail": {},
}

var resourceIDKeys = map[string][]string{
	"s3":         {"bucketName"},
	"ec2":        {"groupId", "instanceId", "networkAclId", "routeTableId", "vpcId"},
	"iam":        {"roleName", "userName", "groupName", "policyArn", "policyName"},
	"rds":        {"dBInstanceIdentifier"},
	"kms":        {"keyId"},
	"cloudtrail": {"name", "trailName"},
}

// CloudChangeEvent is the provider-neutral shape forwarded to the control plane.
// Field names match the Python dataclass / intended Phase 2 ingest JSON.
type CloudChangeEvent struct {
	Provider     string         `json:"provider"`
	Account      string         `json:"account"`
	Region       string         `json:"region"`
	ResourceType string         `json:"resource_type"`
	ResourceID   string         `json:"resource_id"`
	Action       string         `json:"action"`
	ARN          string         `json:"arn,omitempty"`
	Raw          map[string]any `json:"raw,omitempty"`
}

// ParseCloudTrail parses an EventBridge envelope or bare CloudTrail record.
// Returns (nil, nil) for skippable/malformed input (fail-closed, no crash).
func ParseCloudTrail(message []byte) (*CloudChangeEvent, error) {
	var obj map[string]any
	if err := json.Unmarshal(message, &obj); err != nil {
		return nil, nil
	}
	return ParseCloudTrailObject(obj), nil
}

// ParseCloudTrailObject normalizes a decoded JSON object.
func ParseCloudTrailObject(obj map[string]any) *CloudChangeEvent {
	if obj == nil {
		return nil
	}

	detail, _ := obj["detail"].(map[string]any)
	if detail == nil {
		detail = obj
	}

	if dt, ok := obj["detail-type"]; ok && dt != nil {
		if s, ok := dt.(string); !ok || s != CloudTrailDetailType {
			return nil
		}
	}

	source := asString(obj["source"])
	if source == "" {
		source = asString(detail["eventSource"])
	}
	token := canonicalResourceType(source)
	if _, ok := supportedResourceTypes[token]; !ok {
		return nil
	}

	account := strings.TrimSpace(asString(obj["account"]))
	if account == "" {
		account = strings.TrimSpace(asString(detail["recipientAccountId"]))
	}
	if account == "" {
		if ui, ok := detail["userIdentity"].(map[string]any); ok {
			account = strings.TrimSpace(asString(ui["accountId"]))
		}
	}

	action := strings.TrimSpace(asString(detail["eventName"]))
	region := strings.TrimSpace(asString(obj["region"]))
	if region == "" {
		region = strings.TrimSpace(asString(detail["awsRegion"]))
	}
	resourceID := extractResourceID(token, detail)

	if account == "" || action == "" || resourceID == "" {
		return nil
	}

	arn := ""
	if resources, ok := detail["resources"]; ok {
		switch v := resources.(type) {
		case string:
			arn = v
		default:
			// list or other shapes: leave empty (Python does the same for lists)
			arn = ""
		}
	}

	return &CloudChangeEvent{
		Provider:     "aws",
		Account:      account,
		Region:       region,
		ResourceType: token,
		ResourceID:   resourceID,
		Action:       action,
		ARN:          arn,
		Raw:          obj,
	}
}

func canonicalResourceType(source string) string {
	token := strings.ToLower(strings.TrimSpace(source))
	if strings.HasPrefix(token, "aws.") {
		token = token[len("aws."):]
	}
	if strings.HasSuffix(token, ".amazonaws.com") {
		token = token[:len(token)-len(".amazonaws.com")]
	}
	return token
}

func extractResourceID(token string, detail map[string]any) string {
	params := map[string]any{}
	for _, key := range []string{"requestParameters", "responseElements"} {
		if m, ok := detail[key].(map[string]any); ok {
			for k, v := range m {
				params[k] = v
			}
		}
	}
	for _, candidate := range resourceIDKeys[token] {
		if v, ok := params[candidate]; ok {
			if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
				return strings.TrimSpace(s)
			}
		}
	}
	return ""
}

func asString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case fmt.Stringer:
		return t.String()
	case float64:
		// JSON numbers — account ids should be strings; ignore numeric
		return ""
	default:
		if t == nil {
			return ""
		}
		return fmt.Sprint(t)
	}
}
