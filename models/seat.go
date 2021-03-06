// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// Seat Seat
//
// swagger:model Seat
type Seat struct {

	// email
	Email string `json:"email,omitempty"`

	// seat id
	SeatID string `json:"seat_id,omitempty"`

	// seat name
	SeatName string `json:"seat_name,omitempty"`
}

// Validate validates this seat
func (m *Seat) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this seat based on context it is used
func (m *Seat) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *Seat) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *Seat) UnmarshalBinary(b []byte) error {
	var res Seat
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
