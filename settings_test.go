package main

import (
	"testing"

	"github.com/mailru/easyjson"

	kubewarden_protocol "github.com/kubewarden/policy-sdk-go/protocol"
)

func TestParseValidSettings(t *testing.T) {
	settingsJSON := []byte(`
	{
		"denied_annotations": [ "foo", "bar" ],
		"mandatory_annotations": ["owner"],
		"constrained_annotations": {
			"cost-center": "cc-\\d+"
		}
	}`)

	settings, err := newSettings(settingsJSON)
	if err != nil {
		t.Errorf("Unexpected error %+v", err)
	}

	expectedDeniedAnnotations := []string{"foo", "bar"}
	for _, exp := range expectedDeniedAnnotations {
		if !settings.DeniedAnnotations.Contains(exp) {
			t.Errorf("Missing denied annotation %s", exp)
		}
	}

	expectedMandatoryAnnotations := []string{"owner"}
	for _, exp := range expectedMandatoryAnnotations {
		if !settings.MandatoryAnnotations.Contains(exp) {
			t.Errorf("Missing mandatory annotation %s", exp)
		}
	}

	re, found := settings.ConstrainedAnnotations["cost-center"]
	if !found {
		t.Error("Didn't find the expected constrained annotation")
	}

	expectedRegexp := `cc-\d+`
	if re.String() != expectedRegexp {
		t.Errorf("Execpted regexp to be %v - got %v instead",
			expectedRegexp, re.String())
	}
}

func TestParseSettingsWithInvalidRegexp(t *testing.T) {
	settingsJSON := []byte(`
	{
		"denied_annotations": [ "foo", "bar" ],
		"mandatory_annotations": ["owner"],
		"constrained_annotations": {
			"cost-center": "cc-[a+"
		}
	}`)

	_, err := newSettings(settingsJSON)
	if err == nil {
		t.Errorf("Didn'g get expected error")
	}
}

func TestDetectValidSettings(t *testing.T) {
	request := `
	{
		"denied_annotations": [ "foo", "bar" ],
		"mandatory_annotations": ["owner"],
		"constrained_annotations": {
			"cost-center": "cc-\\d+"
		}
	}
	`
	rawRequest := []byte(request)
	responsePayload, err := validateSettings(rawRequest)
	if err != nil {
		t.Errorf("Unexpected error %+v", err)
	}

	var response kubewarden_protocol.SettingsValidationResponse
	if err := easyjson.Unmarshal(responsePayload, &response); err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	if !response.Valid {
		t.Errorf("Expected settings to be valid: %s", *response.Message)
	}
}

func TestDetectNotValidSettingsDueToBrokenRegexp(t *testing.T) {
	request := `
	{
		"denied_annotations": [ "foo", "bar" ],
		"mandatory_annotations": ["owner"],
		"constrained_annotations": {
			"cost-center": "cc-[a+"
		}
	}
	`
	rawRequest := []byte(request)
	responsePayload, err := validateSettings(rawRequest)
	if err != nil {
		t.Errorf("Unexpected error %+v", err)
	}

	var response kubewarden_protocol.SettingsValidationResponse
	if err := easyjson.Unmarshal(responsePayload, &response); err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	if response.Valid {
		t.Error("Expected settings to not be valid")
	}

	if *response.Message != "Provided settings are not valid: Cannot compile regexp cc-[a+: error parsing regexp: missing closing ]: `[a+`" {
		t.Errorf("Unexpected validation error message: %s", *response.Message)
	}
}

func TestDetectNotValidSettingsDueToConflictingDeniedAndConstrainedAnnotations(t *testing.T) {
	request := `
	{
		"denied_annotations": [ "foo", "bar", "cost-center" ],
		"mandatory_annotations": ["owner"],
		"constrained_annotations": {
			"cost-center": ".*"
		}
	}
	`
	rawRequest := []byte(request)
	responsePayload, err := validateSettings(rawRequest)
	if err != nil {
		t.Errorf("Unexpected error %+v", err)
	}

	var response kubewarden_protocol.SettingsValidationResponse
	if err := easyjson.Unmarshal(responsePayload, &response); err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	if response.Valid {
		t.Error("Expected settings to not be valid")
	}

	if *response.Message != "Provided settings are not valid: These annotations cannot be constrained and denied at the same time: cost-center" {
		t.Errorf("Unexpected validation error message: %s", *response.Message)
	}
}

func TestDetectNotValidSettingsDueToConflictingDeniedAndMandatoryAnnotations(t *testing.T) {
	request := `
	{
		"denied_annotations": [ "foo", "bar", "owner" ],
		"mandatory_annotations": ["owner"],
		"constrained_annotations": {
			"cost-center": ".*"
		}
	}
	`
	rawRequest := []byte(request)
	responsePayload, err := validateSettings(rawRequest)
	if err != nil {
		t.Errorf("Unexpected error %+v", err)
	}

	var response kubewarden_protocol.SettingsValidationResponse
	if err := easyjson.Unmarshal(responsePayload, &response); err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	if response.Valid {
		t.Error("Expected settings to not be valid")
	}

	if *response.Message != "Provided settings are not valid: These annotations cannot be mandatory and denied at the same time: owner" {
		t.Errorf("Unexpected validation error message: %s", *response.Message)
	}
}
