// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// GetEnrollStatusResponse GetEnrollStatusResponse
//
// swagger:model GetEnrollStatusResponse
type GetEnrollStatusResponse struct {

	// certificates
	Certificates []string `json:"certificates"`

	// created at
	CreatedAt string `json:"created_at,omitempty"`

	// profile id
	ProfileID string `json:"profile_id,omitempty"`

	// status
	Status string `json:"status,omitempty"`

	// updated at
	UpdatedAt string `json:"updated_at,omitempty"`
}

// Validate validates this get enroll status response
func (m *GetEnrollStatusResponse) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this get enroll status response based on context it is used
func (m *GetEnrollStatusResponse) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *GetEnrollStatusResponse) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *GetEnrollStatusResponse) UnmarshalBinary(b []byte) error {
	var res GetEnrollStatusResponse
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
