package main

import (
	"encoding/json"
	"testing"

	mapset "github.com/deckarep/golang-set"
	kubewarden_testing "github.com/kubewarden/policy-sdk-go/testing"
)

func TestEmptySettingsLeadsToRequestAccepted(t *testing.T) {
	settings := Settings{
		DeniedAnnotations:      mapset.NewThreadUnsafeSet(),
		MandatoryAnnotations:   mapset.NewThreadUnsafeSet(),
		ConstrainedAnnotations: make(map[string]*RegularExpression),
	}

	payload, err := kubewarden_testing.BuildValidationRequest(
		"test_data/ingress.json",
		&settings)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	responsePayload, err := validate(payload)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	var response kubewarden_testing.ValidationResponse
	if err := json.Unmarshal(responsePayload, &response); err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	if response.Accepted != true {
		t.Error("Unexpected rejection")
	}
}

func TestRequestAccepted(t *testing.T) {
	constrainedAnnotations := make(map[string]*RegularExpression)
	re, err := CompileRegularExpression(`^world-`)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}
	constrainedAnnotations["hello"] = re

	settings := Settings{
		DeniedAnnotations:      mapset.NewThreadUnsafeSetFromSlice([]interface{}{"bad1", "bad2"}),
		MandatoryAnnotations:   mapset.NewThreadUnsafeSet(),
		ConstrainedAnnotations: constrainedAnnotations,
	}

	payload, err := kubewarden_testing.BuildValidationRequest(
		"test_data/ingress.json",
		&settings)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	responsePayload, err := validate(payload)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	var response kubewarden_testing.ValidationResponse
	if err := json.Unmarshal(responsePayload, &response); err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	if response.Accepted != true {
		t.Error("Unexpected rejection")
	}
}

func TestAcceptRequestWithConstrainedAnnotation(t *testing.T) {
	constrainedAnnotations := make(map[string]*RegularExpression)
	re, err := CompileRegularExpression(`^team-`)
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}
	constrainedAnnotations["owner"] = re
	settings := Settings{
		DeniedAnnotations:      mapset.NewThreadUnsafeSetFromSlice([]interface{}{"bad1", "bad2"}),
		MandatoryAnnotations:   mapset.NewThreadUnsafeSet(),
		ConstrainedAnnotations: constrainedAnnotations,
	}

	payload, err := kubewarden_testing.BuildValidationRequest(
		"test_data/ingress.json",
		&settings)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	responsePayload, err := validate(payload)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	var response kubewarden_testing.ValidationResponse
	if err := json.Unmarshal(responsePayload, &response); err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	if response.Accepted != true {
		t.Error("Unexpected rejection")
	}
}

func TestRejectionBecauseDeniedAnnotation(t *testing.T) {
	constrainedAnnotations := make(map[string]*RegularExpression)
	re, err := CompileRegularExpression(`^world-`)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}
	constrainedAnnotations["hello"] = re

	settings := Settings{
		DeniedAnnotations:      mapset.NewThreadUnsafeSetFromSlice([]interface{}{"owner"}),
		MandatoryAnnotations:   mapset.NewThreadUnsafeSet(),
		ConstrainedAnnotations: constrainedAnnotations,
	}

	payload, err := kubewarden_testing.BuildValidationRequest(
		"test_data/ingress.json",
		&settings)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	responsePayload, err := validate(payload)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	var response kubewarden_testing.ValidationResponse
	if err := json.Unmarshal(responsePayload, &response); err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	if response.Accepted != false {
		t.Error("Unexpected accept response")
	}

	expected_message := "The following annotations are denied: owner"
	if response.Message != expected_message {
		t.Errorf("Got '%s' instead of '%s'", response.Message, expected_message)
	}
}

func TestRejectionBecauseConstrainedAnnotationNotValid(t *testing.T) {
	constrainedAnnotations := make(map[string]*RegularExpression)
	re, err := CompileRegularExpression(`^cc-\d+$`)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}
	constrainedAnnotations["cc-center"] = re

	settings := Settings{
		DeniedAnnotations:      mapset.NewThreadUnsafeSet(),
		MandatoryAnnotations:   mapset.NewThreadUnsafeSet(),
		ConstrainedAnnotations: constrainedAnnotations,
	}

	payload, err := kubewarden_testing.BuildValidationRequest(
		"test_data/ingress.json",
		&settings)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	responsePayload, err := validate(payload)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	var response kubewarden_testing.ValidationResponse
	if err := json.Unmarshal(responsePayload, &response); err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	if response.Accepted != false {
		t.Error("Unexpected accept response")
	}

	expected_message := "The following annotations are violating user constraints: cc-center"
	if response.Message != expected_message {
		t.Errorf("Got '%s' instead of '%s'", response.Message, expected_message)
	}
}

func TestRejectionBecauseConstrainedAnnotationMissing(t *testing.T) {
	settings := Settings{
		DeniedAnnotations:      mapset.NewThreadUnsafeSet(),
		MandatoryAnnotations:   mapset.NewThreadUnsafeSetFromSlice([]interface{}{"required"}),
		ConstrainedAnnotations: make(map[string]*RegularExpression),
	}

	payload, err := kubewarden_testing.BuildValidationRequest(
		"test_data/ingress.json",
		&settings)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	responsePayload, err := validate(payload)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	var response kubewarden_testing.ValidationResponse
	if err := json.Unmarshal(responsePayload, &response); err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	if response.Accepted != false {
		t.Error("Unexpected accept response")
	}

	expected_message := "The following mandatory annotations are missing: required"
	if response.Message != expected_message {
		t.Errorf("Got '%s' instead of '%s'", response.Message, expected_message)
	}
}
