// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// RequestCertificateRequest RequestCertificateRequest
//
// swagger:model RequestCertificateRequest
type RequestCertificateRequest struct {

	// attributes
	Attributes *CertificateAttributes `json:"attributes,omitempty"`

	// authentication
	Authentication map[string]string `json:"authentication,omitempty"`

	// csr
	Csr string `json:"csr,omitempty"`

	// profile
	Profile *Profile `json:"profile,omitempty"`

	// seat
	Seat *Seat `json:"seat,omitempty"`

	// session key
	SessionKey string `json:"session_key,omitempty"`

	// Validity of certificate only for enroll certificate API.It is not supported for renewal API
	Validity *Validity `json:"validity,omitempty"`
}

// Validate validates this request certificate request
func (m *RequestCertificateRequest) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAttributes(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateProfile(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSeat(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateValidity(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *RequestCertificateRequest) validateAttributes(formats strfmt.Registry) error {
	if swag.IsZero(m.Attributes) { // not required
		return nil
	}

	if m.Attributes != nil {
		if err := m.Attributes.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("attributes")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("attributes")
			}
			return err
		}
	}

	return nil
}

func (m *RequestCertificateRequest) validateProfile(formats strfmt.Registry) error {
	if swag.IsZero(m.Profile) { // not required
		return nil
	}

	if m.Profile != nil {
		if err := m.Profile.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("profile")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("profile")
			}
			return err
		}
	}

	return nil
}

func (m *RequestCertificateRequest) validateSeat(formats strfmt.Registry) error {
	if swag.IsZero(m.Seat) { // not required
		return nil
	}

	if m.Seat != nil {
		if err := m.Seat.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("seat")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("seat")
			}
			return err
		}
	}

	return nil
}

func (m *RequestCertificateRequest) validateValidity(formats strfmt.Registry) error {
	if swag.IsZero(m.Validity) { // not required
		return nil
	}

	if m.Validity != nil {
		if err := m.Validity.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("validity")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("validity")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this request certificate request based on the context it is used
func (m *RequestCertificateRequest) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateAttributes(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateProfile(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateSeat(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateValidity(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *RequestCertificateRequest) contextValidateAttributes(ctx context.Context, formats strfmt.Registry) error {

	if m.Attributes != nil {
		if err := m.Attributes.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("attributes")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("attributes")
			}
			return err
		}
	}

	return nil
}

func (m *RequestCertificateRequest) contextValidateProfile(ctx context.Context, formats strfmt.Registry) error {

	if m.Profile != nil {
		if err := m.Profile.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("profile")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("profile")
			}
			return err
		}
	}

	return nil
}

func (m *RequestCertificateRequest) contextValidateSeat(ctx context.Context, formats strfmt.Registry) error {

	if m.Seat != nil {
		if err := m.Seat.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("seat")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("seat")
			}
			return err
		}
	}

	return nil
}

func (m *RequestCertificateRequest) contextValidateValidity(ctx context.Context, formats strfmt.Registry) error {

	if m.Validity != nil {
		if err := m.Validity.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("validity")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("validity")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *RequestCertificateRequest) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *RequestCertificateRequest) UnmarshalBinary(b []byte) error {
	var res RequestCertificateRequest
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
