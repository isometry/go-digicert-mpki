// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// UpdateSeatRequest UpdateSeatRequest
//
// swagger:model UpdateSeatRequest
type UpdateSeatRequest struct {

	// email
	Email string `json:"email,omitempty"`

	// phone
	Phone string `json:"phone,omitempty"`

	// seat name
	SeatName string `json:"seat_name,omitempty"`
}

// Validate validates this update seat request
func (m *UpdateSeatRequest) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this update seat request based on context it is used
func (m *UpdateSeatRequest) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *UpdateSeatRequest) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *UpdateSeatRequest) UnmarshalBinary(b []byte) error {
	var res UpdateSeatRequest
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
