package main

import (
	mapset "github.com/deckarep/golang-set"
	kubewarden "github.com/kubewarden/policy-sdk-go"
	kubewarden_protocol "github.com/kubewarden/policy-sdk-go/protocol"
	easyjson "github.com/mailru/easyjson"

	"fmt"
	"regexp"
	"strings"
)

type Settings struct {
	DeniedAnnotations      mapset.Set                `json:"denied_annotations"`
	MandatoryAnnotations   mapset.Set                `json:"mandatory_annotations"`
	ConstrainedAnnotations map[string]*regexp.Regexp `json:"constrained_annotations"`
}

// Builds a new Settings instance starting from a validation
// request payload:
// {
//    "request": ...,
//    "settings": {
//       "denied_annotations": [...],
//       "mandatory_annotations": [...],
//       "constrained_annotations": { ... }
//    }
// }
func NewSettingsFromValidationReq(validationReq kubewarden_protocol.ValidationRequest) (Settings, error) {
	return newSettings(validationReq.Settings)
}

func newSettings(settingsJson []byte) (Settings, error) {
	basicSettings := BasicSettings{}
	err := easyjson.Unmarshal(settingsJson, &basicSettings)
	if err != nil {
		return Settings{}, err
	}

	deniedAnnotations := mapset.NewThreadUnsafeSet()
	for _, label := range basicSettings.DeniedAnnotations {
		deniedAnnotations.Add(label)
	}

	mandatoryAnnotations := mapset.NewThreadUnsafeSet()
	for _, label := range basicSettings.MandatoryAnnotations {
		mandatoryAnnotations.Add(label)
	}

	constrainedAnnotations := make(map[string]*regexp.Regexp)
	for name, expr := range basicSettings.ConstrainedAnnotations {
		reg, err := regexp.Compile(expr)
		if err != nil {
			return Settings{}, fmt.Errorf("Cannot compile regexp %s: %v", expr, err)
		}
		constrainedAnnotations[name] = reg
	}

	return Settings{
		DeniedAnnotations:      deniedAnnotations,
		MandatoryAnnotations:   mandatoryAnnotations,
		ConstrainedAnnotations: constrainedAnnotations,
	}, nil
}

func (s *Settings) Valid() (bool, error) {
	constrainedAnnotations := mapset.NewThreadUnsafeSet()

	for annotations := range s.ConstrainedAnnotations {
		constrainedAnnotations.Add(annotations)
	}

	errors := []string{}

	constrainedAndDenied := constrainedAnnotations.Intersect(s.DeniedAnnotations)
	if constrainedAndDenied.Cardinality() != 0 {
		violations := []string{}
		for _, v := range constrainedAndDenied.ToSlice() {
			violations = append(violations, v.(string))
		}
		errors = append(
			errors,
			fmt.Sprintf(
				"These annotations cannot be constrained and denied at the same time: %s",
				strings.Join(violations, ","),
			),
		)
	}

	mandatoryAndDenied := s.MandatoryAnnotations.Intersect(s.DeniedAnnotations)
	if mandatoryAndDenied.Cardinality() != 0 {
		violations := []string{}
		for _, v := range mandatoryAndDenied.ToSlice() {
			violations = append(violations, v.(string))
		}
		errors = append(
			errors,
			fmt.Sprintf(
				"These annotations cannot be mandatory and denied at the same time: %s",
				strings.Join(violations, ","),
			),
		)
	}

	if len(errors) > 0 {
		return false, fmt.Errorf("%s", strings.Join(errors, "; "))
	}
	return true, nil
}

func validateSettings(payload []byte) ([]byte, error) {
	settings, err := newSettings(payload)
	if err != nil {
		// this happens when one of the user-defined regular expressions are invalid
		return kubewarden.RejectSettings(
			kubewarden.Message(fmt.Sprintf("Provided settings are not valid: %v", err)))
	}

	valid, err := settings.Valid()
	if valid {
		return kubewarden.AcceptSettings()
	}
	return kubewarden.RejectSettings(
		kubewarden.Message(fmt.Sprintf("Provided settings are not valid: %v", err)))
}
