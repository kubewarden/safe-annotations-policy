package main

import (
	"fmt"

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

	data.ForEach(func(key, value gjson.Result) bool {
		annotation := key.String()

		if settings.DeniedAnnotations.Contains(annotation) {
			err = fmt.Errorf("Annotation %s is on the deny list", annotation)
			// stop iterating over annotations
			return false
		}

		regExp, found := settings.ConstrainedAnnotations[annotation]
		if found {
			// This is a constrained annotation
			if !regExp.Match([]byte(value.String())) {
				err = fmt.Errorf("The value of %s doesn't pass user-defined constraint", annotation)
				// stop iterating over annotations
				return false
			}
		}

		return true
	})

	if err != nil {
		return kubewarden.RejectRequest(
			kubewarden.Message(err.Error()),
			kubewarden.NoCode)
	}

	return kubewarden.AcceptRequest()
}
