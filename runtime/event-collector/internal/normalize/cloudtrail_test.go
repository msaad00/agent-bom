package normalize

import (
	"encoding/json"
	"testing"
)

func sampleS3Envelope(account, bucket string) []byte {
	obj := map[string]any{
		"detail-type": "AWS API Call via CloudTrail",
		"source":      "aws.s3",
		"account":     account,
		"region":      "us-east-1",
		"detail": map[string]any{
			"eventSource":        "s3.amazonaws.com",
			"eventName":          "PutBucketPolicy",
			"awsRegion":          "us-east-1",
			"recipientAccountId": account,
			"userIdentity":       map[string]any{"accountId": account},
			"requestParameters":  map[string]any{"bucketName": bucket},
		},
	}
	b, err := json.Marshal(obj)
	if err != nil {
		panic(err)
	}
	return b
}

func TestParseCloudTrailS3PutBucketPolicy(t *testing.T) {
	ev, err := ParseCloudTrail(sampleS3Envelope("123456789012", "public-bucket"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ev == nil {
		t.Fatal("expected event, got nil")
	}
	if ev.Provider != "aws" || ev.Account != "123456789012" || ev.Region != "us-east-1" {
		t.Fatalf("unexpected identity fields: %+v", ev)
	}
	if ev.ResourceType != "s3" || ev.ResourceID != "public-bucket" || ev.Action != "PutBucketPolicy" {
		t.Fatalf("unexpected resource fields: %+v", ev)
	}
}

func TestParseCloudTrailMalformedReturnsNil(t *testing.T) {
	cases := []string{
		`{"detail-type":"Some Other Event","source":"aws.s3","account":"123456789012","detail":{}}`,
		`{"source":"aws.s3","account":"123456789012","detail":{"eventName":"PutBucketPolicy"}}`,
		`{"source":"aws.s3","detail":{"eventName":"Put","requestParameters":{"bucketName":"b"}}}`,
		`{"source":"aws.dynamodb","account":"123456789012","detail":{"eventName":"X","requestParameters":{"k":"v"}}}`,
		`not-json`,
	}
	for _, msg := range cases {
		ev, err := ParseCloudTrail([]byte(msg))
		if err != nil {
			t.Fatalf("unexpected error for %q: %v", msg, err)
		}
		if ev != nil {
			t.Fatalf("expected nil for %q, got %+v", msg, ev)
		}
	}
}

func TestParseCloudTrailBareRecord(t *testing.T) {
	bare := []byte(`{
		"eventSource": "iam.amazonaws.com",
		"eventName": "CreateUser",
		"awsRegion": "us-west-2",
		"recipientAccountId": "111122223333",
		"requestParameters": {"userName": "alice"}
	}`)
	ev, err := ParseCloudTrail(bare)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ev == nil {
		t.Fatal("expected event")
	}
	if ev.ResourceType != "iam" || ev.ResourceID != "alice" || ev.Action != "CreateUser" {
		t.Fatalf("unexpected: %+v", ev)
	}
}
