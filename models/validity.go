// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// Validity Validity
//
// swagger:model Validity
type Validity struct {

	// duration
	Duration int32 `json:"duration,omitempty"`

	// unit
	Unit string `json:"unit,omitempty"`
}

// Validate validates this validity
func (m *Validity) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this validity based on context it is used
func (m *Validity) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *Validity) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *Validity) UnmarshalBinary(b []byte) error {
	var res Validity
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}