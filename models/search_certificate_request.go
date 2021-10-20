// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// SearchCertificateRequest SearchCertificateRequest
//
// swagger:model SearchCertificateRequest
type SearchCertificateRequest struct {

	// common name
	CommonName string `json:"common_name,omitempty"`

	// email
	Email string `json:"email,omitempty"`

	// issuing ca
	IssuingCa string `json:"issuing_ca,omitempty"`

	// profile id
	ProfileID string `json:"profile_id,omitempty"`

	// seat id
	SeatID string `json:"seat_id,omitempty"`

	// serial number
	SerialNumber string `json:"serial_number,omitempty"`

	// start index
	StartIndex int32 `json:"start_index,omitempty"`

	// status
	Status string `json:"status,omitempty"`

	// valid from
	ValidFrom string `json:"valid_from,omitempty"`

	// valid to
	ValidTo string `json:"valid_to,omitempty"`
}

// Validate validates this search certificate request
func (m *SearchCertificateRequest) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this search certificate request based on context it is used
func (m *SearchCertificateRequest) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *SearchCertificateRequest) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *SearchCertificateRequest) UnmarshalBinary(b []byte) error {
	var res SearchCertificateRequest
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
