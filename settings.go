package main

import (
	"github.com/deckarep/golang-set"
	"github.com/kubewarden/gjson"
	kubewarden "github.com/kubewarden/policy-sdk-go"

	"fmt"
	"regexp"
)

// A wrapper around the standard regexp.Regexp struct
// that implements marshalling and unmarshalling
type RegularExpression struct {
	*regexp.Regexp
}

// Convenience method to build a regular expression
func CompileRegularExpression(expr string) (*RegularExpression, error) {
	nativeRegExp, err := regexp.Compile(expr)
	if err != nil {
		return nil, err
	}
	return &RegularExpression{nativeRegExp}, nil
}

// UnmarshalText satisfies the encoding.TextMarshaler interface,
// also used by json.Unmarshal.
func (r *RegularExpression) UnmarshalText(text []byte) error {
	nativeRegExp, err := regexp.Compile(string(text))
	if err != nil {
		return err
	}
	r.Regexp = nativeRegExp
	return nil
}

// MarshalText satisfies the encoding.TextMarshaler interface,
// also used by json.Marshal.
func (r *RegularExpression) MarshalText() ([]byte, error) {
	if r.Regexp != nil {
		return []byte(r.Regexp.String()), nil
	}

	return nil, nil
}

type Settings struct {
	DeniedAnnotations      mapset.Set                    `json:"denied_annotations"`
	ConstrainedAnnotations map[string]*RegularExpression `json:"constrained_annotations"`
}

// Builds a new Settings instance starting from a validation
// request payload:
// {
//    "request": ...,
//    "settings": {
//       "denied_annotations": [...],
//       "constrained_annotations": { ... }
//    }
// }
func NewSettingsFromValidationReq(payload []byte) (Settings, error) {
	// Note well: we don't validate the input JSON now, this has
	// already done inside of the `validate` function

	return newSettings(
		payload,
		"settings.denied_annotations",
		"settings.constrained_annotations")
}

// Builds a new Settings instance starting from a Settings
// payload:
// {
//    "denied_names": [ ... ],
//    "constrained_annotations": { ... }
// }
func NewSettingsFromValidateSettingsPayload(payload []byte) (Settings, error) {
	if !gjson.ValidBytes(payload) {
		return Settings{}, fmt.Errorf("denied JSON payload")
	}

	return newSettings(
		payload,
		"denied_annotations",
		"constrained_annotations")
}

func newSettings(payload []byte, paths ...string) (Settings, error) {
	if len(paths) != 2 {
		return Settings{}, fmt.Errorf("wrong number of json paths")
	}

	data := gjson.GetManyBytes(payload, paths...)

	deniedAnnotations := mapset.NewThreadUnsafeSet()
	data[0].ForEach(func(_, entry gjson.Result) bool {
		deniedAnnotations.Add(entry.String())
		return true
	})

	constrainedAnnotations := make(map[string]*RegularExpression)
	var err error
	data[1].ForEach(func(key, value gjson.Result) bool {
		var regExp *RegularExpression
		regExp, err = CompileRegularExpression(value.String())
		if err != nil {
			return false
		}

		constrainedAnnotations[key.String()] = regExp
		return true
	})
	if err != nil {
		return Settings{}, err
	}

	return Settings{
		DeniedAnnotations:      deniedAnnotations,
		ConstrainedAnnotations: constrainedAnnotations,
	}, nil
}

func (s *Settings) Valid() (bool, error) {
	constrainedAnnotations := mapset.NewThreadUnsafeSet()

	for annotation := range s.ConstrainedAnnotations {
		constrainedAnnotations.Add(annotation)
	}

	constrainedAndDenied := constrainedAnnotations.Intersect(s.DeniedAnnotations)
	if constrainedAndDenied.Cardinality() != 0 {
		return false,
			fmt.Errorf("These annotations cannot be constrained and denied at the same time: %v", constrainedAndDenied)
	}

	return true, nil
}

func validateSettings(payload []byte) ([]byte, error) {
	settings, err := NewSettingsFromValidateSettingsPayload(payload)
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
