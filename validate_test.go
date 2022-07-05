package main

import (
	"testing"

	"github.com/mailru/easyjson"

	kubewarden_protocol "github.com/kubewarden/policy-sdk-go/protocol"
	kubewarden_testing "github.com/kubewarden/policy-sdk-go/testing"
)

func TestEmptySettingsLeadsToRequestAccepted(t *testing.T) {
	basicSettings := BasicSettings{
		DeniedAnnotations:      []string{},
		MandatoryAnnotations:   []string{},
		ConstrainedAnnotations: make(map[string]string),
	}

	payload, err := kubewarden_testing.BuildValidationRequestFromFixture(
		"test_data/ingress.json",
		&basicSettings)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	responsePayload, err := validate(payload)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	var response kubewarden_protocol.ValidationResponse
	if err := easyjson.Unmarshal(responsePayload, &response); err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	if response.Accepted != true {
		t.Error("Unexpected rejection")
	}
}

func TestRequestAccepted(t *testing.T) {
	constrainedAnnotations := make(map[string]string)
	constrainedAnnotations["hello"] = `^world-`

	basicSettings := BasicSettings{
		DeniedAnnotations:      []string{"bad1", "bad2"},
		MandatoryAnnotations:   []string{},
		ConstrainedAnnotations: constrainedAnnotations,
	}

	payload, err := kubewarden_testing.BuildValidationRequestFromFixture(
		"test_data/ingress.json",
		&basicSettings)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	responsePayload, err := validate(payload)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	var response kubewarden_protocol.ValidationResponse
	if err := easyjson.Unmarshal(responsePayload, &response); err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	if response.Accepted != true {
		t.Error("Unexpected rejection")
	}
}

func TestAcceptRequestWithConstrainedAnnotation(t *testing.T) {
	constrainedAnnotations := make(map[string]string)
	constrainedAnnotations["owner"] = `^team-`

	basicSettings := BasicSettings{
		DeniedAnnotations:      []string{"bad1", "bad2"},
		MandatoryAnnotations:   []string{},
		ConstrainedAnnotations: constrainedAnnotations,
	}

	payload, err := kubewarden_testing.BuildValidationRequestFromFixture(
		"test_data/ingress.json",
		&basicSettings)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	responsePayload, err := validate(payload)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	var response kubewarden_protocol.ValidationResponse
	if err := easyjson.Unmarshal(responsePayload, &response); err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	if response.Accepted != true {
		t.Error("Unexpected rejection")
	}
}

func TestRejectionBecauseDeniedAnnotation(t *testing.T) {
	constrainedAnnotations := make(map[string]string)
	constrainedAnnotations["hello"] = `^world-`

	basicSettings := BasicSettings{
		DeniedAnnotations:      []string{"owner"},
		MandatoryAnnotations:   []string{},
		ConstrainedAnnotations: constrainedAnnotations,
	}

	payload, err := kubewarden_testing.BuildValidationRequestFromFixture(
		"test_data/ingress.json",
		&basicSettings)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	responsePayload, err := validate(payload)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	var response kubewarden_protocol.ValidationResponse
	if err := easyjson.Unmarshal(responsePayload, &response); err != nil {
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
	constrainedAnnotations := make(map[string]string)
	constrainedAnnotations["cc-center"] = `^cc-\d+$`

	basicSettings := BasicSettings{
		DeniedAnnotations:      []string{},
		MandatoryAnnotations:   []string{},
		ConstrainedAnnotations: constrainedAnnotations,
	}

	payload, err := kubewarden_testing.BuildValidationRequestFromFixture(
		"test_data/ingress.json",
		&basicSettings)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	responsePayload, err := validate(payload)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	var response kubewarden_protocol.ValidationResponse
	if err := easyjson.Unmarshal(responsePayload, &response); err != nil {
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
	settings := BasicSettings{
		DeniedAnnotations:      []string{},
		MandatoryAnnotations:   []string{"required"},
		ConstrainedAnnotations: make(map[string]string),
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
	if err := easyjson.Unmarshal(responsePayload, &response); err != nil {
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
