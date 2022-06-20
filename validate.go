package main

import (
	"fmt"
	"strings"

	mapset "github.com/deckarep/golang-set"
	"github.com/kubewarden/gjson"
	kubewarden "github.com/kubewarden/policy-sdk-go"
)

func validate(payload []byte) ([]byte, error) {
	if !gjson.ValidBytes(payload) {
		return kubewarden.RejectRequest(
			kubewarden.Message("Not a valid JSON document"),
			kubewarden.Code(400))
	}

	settings, err := NewSettingsFromValidationReq(payload)
	if err != nil {
		return kubewarden.RejectRequest(
			kubewarden.Message(err.Error()),
			kubewarden.Code(400))
	}

	data := gjson.GetBytes(
		payload,
		"request.object.metadata.annotations")

	annotations := mapset.NewThreadUnsafeSet()
	denied_annotations_violations := []string{}
	constrained_annotations_violations := []string{}

	data.ForEach(func(key, value gjson.Result) bool {
		annotation := key.String()
		annotations.Add(annotation)

		if settings.DeniedAnnotations.Contains(annotation) {
			denied_annotations_violations = append(denied_annotations_violations, annotation)
			return true
		}

		regExp, found := settings.ConstrainedAnnotations[annotation]
		if found {
			// This is a constrained annotation
			if !regExp.Match([]byte(value.String())) {
				constrained_annotations_violations = append(constrained_annotations_violations, annotation)
				return true
			}
		}

		return true
	})

	error_msgs := []string{}

	if len(denied_annotations_violations) > 0 {
		error_msgs = append(
			error_msgs,
			fmt.Sprintf(
				"The following annotations are not allowed: %s",
				strings.Join(denied_annotations_violations, ","),
			))
	}

	if len(constrained_annotations_violations) > 0 {
		error_msgs = append(
			error_msgs,
			fmt.Sprintf(
				"The following annotations are violating user constraints: %s",
				strings.Join(constrained_annotations_violations, ","),
			))
	}

	mandatory_annotations_violations := settings.MandatoryAnnotations.Difference(annotations)
	if mandatory_annotations_violations.Cardinality() > 0 {
		violations := []string{}
		for _, v := range mandatory_annotations_violations.ToSlice() {
			violations = append(violations, v.(string))
		}

		error_msgs = append(
			error_msgs,
			fmt.Sprintf(
				"The following mandatory annotations are missing: %s",
				strings.Join(violations, ","),
			))
	}

	if len(error_msgs) > 0 {
		return kubewarden.RejectRequest(
			kubewarden.Message(strings.Join(error_msgs, ". ")),
			kubewarden.NoCode)
	}

	return kubewarden.AcceptRequest()
}
