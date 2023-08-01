package main

import (
	"regexp"
	"testing"

	"encoding/json"

	mapset "github.com/deckarep/golang-set/v2"
	kubewarden_protocol "github.com/kubewarden/policy-sdk-go/protocol"
	kubewarden_testing "github.com/kubewarden/policy-sdk-go/testing"
)

func TestEmptySettingsLeadsToRequestAccepted(t *testing.T) {
	settings := Settings{
		DeniedAnnotations:      mapset.NewThreadUnsafeSet[string](),
		MandatoryAnnotations:   mapset.NewThreadUnsafeSet[string](),
		ConstrainedAnnotations: map[string]*RegularExpression{},
	}

	payload, err := kubewarden_testing.BuildValidationRequestFromFixture(
		"test_data/ingress.json",
		&settings)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	responsePayload, err := validate(payload)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	var response kubewarden_protocol.ValidationResponse
	if err := json.Unmarshal(responsePayload, &response); err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	if response.Accepted != true {
		t.Error("Unexpected rejection")
	}
}

func TestRequestAccepted(t *testing.T) {
	settings := Settings{
		DeniedAnnotations:    mapset.NewThreadUnsafeSet("bad1", "bad2"),
		MandatoryAnnotations: mapset.NewThreadUnsafeSet[string](),
		ConstrainedAnnotations: map[string]*RegularExpression{
			"hello": {
				Regexp: regexp.MustCompile(`^world-`),
			},
		},
	}

	payload, err := kubewarden_testing.BuildValidationRequestFromFixture(
		"test_data/ingress.json",
		&settings)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	responsePayload, err := validate(payload)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	var response kubewarden_protocol.ValidationResponse
	if err := json.Unmarshal(responsePayload, &response); err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	if response.Accepted != true {
		t.Error("Unexpected rejection")
	}
}

func TestAcceptRequestWithConstrainedAnnotation(t *testing.T) {
	settings := Settings{
		DeniedAnnotations:    mapset.NewThreadUnsafeSet("bad1", "bad2"),
		MandatoryAnnotations: mapset.NewThreadUnsafeSet[string](),
		ConstrainedAnnotations: map[string]*RegularExpression{
			"owner": {
				Regexp: regexp.MustCompile(`^team-`),
			},
		},
	}

	payload, err := kubewarden_testing.BuildValidationRequestFromFixture(
		"test_data/ingress.json",
		&settings)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	responsePayload, err := validate(payload)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	var response kubewarden_protocol.ValidationResponse
	if err := json.Unmarshal(responsePayload, &response); err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	if response.Accepted != true {
		t.Error("Unexpected rejection")
	}
}

func TestRejectionBecauseDeniedAnnotation(t *testing.T) {
	settings := Settings{
		DeniedAnnotations:    mapset.NewThreadUnsafeSet("owner"),
		MandatoryAnnotations: mapset.NewThreadUnsafeSet[string](),
		ConstrainedAnnotations: map[string]*RegularExpression{
			"hello": {
				Regexp: regexp.MustCompile(`^world-`),
			},
		},
	}

	payload, err := kubewarden_testing.BuildValidationRequestFromFixture(
		"test_data/ingress.json",
		&settings)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	responsePayload, err := validate(payload)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	var response kubewarden_protocol.ValidationResponse
	if err := json.Unmarshal(responsePayload, &response); err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	if response.Accepted != false {
		t.Error("Unexpected accept response")
	}

	expectedMessage := "The following annotations are not allowed: owner"
	if *response.Message != expectedMessage {
		t.Errorf("Got '%s' instead of '%s'", *response.Message, expectedMessage)
	}
}

func TestRejectionBecauseConstrainedAnnotationNotValid(t *testing.T) {
	settings := Settings{
		DeniedAnnotations:    mapset.NewThreadUnsafeSet[string](),
		MandatoryAnnotations: mapset.NewThreadUnsafeSet[string](),
		ConstrainedAnnotations: map[string]*RegularExpression{
			"cc-center": {
				Regexp: regexp.MustCompile(`^cc-\d+$`),
			},
		},
	}

	payload, err := kubewarden_testing.BuildValidationRequestFromFixture(
		"test_data/ingress.json",
		&settings)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	responsePayload, err := validate(payload)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	var response kubewarden_protocol.ValidationResponse
	if err := json.Unmarshal(responsePayload, &response); err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	if response.Accepted != false {
		t.Error("Unexpected accept response")
	}

	expectedMessage := "The following annotations are violating user constraints: cc-center"
	if *response.Message != expectedMessage {
		t.Errorf("Got '%s' instead of '%s'", *response.Message, expectedMessage)
	}
}

func TestRejectionBecauseMandatoryAnnotationMissing(t *testing.T) {
	settings := Settings{
		DeniedAnnotations:      mapset.NewThreadUnsafeSet[string](),
		MandatoryAnnotations:   mapset.NewThreadUnsafeSet("required"),
		ConstrainedAnnotations: map[string]*RegularExpression{},
	}

	payload, err := kubewarden_testing.BuildValidationRequestFromFixture(
		"test_data/ingress.json",
		&settings)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	responsePayload, err := validate(payload)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	var response kubewarden_protocol.ValidationResponse
	if err := json.Unmarshal(responsePayload, &response); err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	if response.Accepted != false {
		t.Error("Unexpected accept response")
	}

	expectedMessage := "The following mandatory annotations are missing: required"
	if *response.Message != expectedMessage {
		t.Errorf("Got '%s' instead of '%s'", *response.Message, expectedMessage)
	}
}
