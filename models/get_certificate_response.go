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

// GetCertificateResponse GetCertificateResponse
//
// swagger:model GetCertificateResponse
type GetCertificateResponse struct {

	// account
	Account *Account `json:"account,omitempty"`

	// certificate
	Certificate string `json:"certificate,omitempty"`

	// common name
	CommonName string `json:"common_name,omitempty"`

	// enrollment notes
	EnrollmentNotes string `json:"enrollment_notes,omitempty"`

	// is key escrowed
	IsKeyEscrowed bool `json:"is_key_escrowed,omitempty"`

	// password
	Password string `json:"password,omitempty"`

	// profile
	Profile *Profile `json:"profile,omitempty"`

	// revocation
	Revocation *Revocation `json:"revocation,omitempty"`

	// seat
	Seat *Seat `json:"seat,omitempty"`

	// serial number
	SerialNumber string `json:"serial_number,omitempty"`

	// session key
	SessionKey string `json:"session_key,omitempty"`

	// status
	Status string `json:"status,omitempty"`

	// valid from
	ValidFrom string `json:"valid_from,omitempty"`

	// valid to
	ValidTo string `json:"valid_to,omitempty"`

	// webpin
	Webpin string `json:"webpin,omitempty"`
}

// Validate validates this get certificate response
func (m *GetCertificateResponse) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAccount(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateProfile(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRevocation(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSeat(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *GetCertificateResponse) validateAccount(formats strfmt.Registry) error {
	if swag.IsZero(m.Account) { // not required
		return nil
	}

	if m.Account != nil {
		if err := m.Account.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("account")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("account")
			}
			return err
		}
	}

	return nil
}

func (m *GetCertificateResponse) validateProfile(formats strfmt.Registry) error {
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

func (m *GetCertificateResponse) validateRevocation(formats strfmt.Registry) error {
	if swag.IsZero(m.Revocation) { // not required
		return nil
	}

	if m.Revocation != nil {
		if err := m.Revocation.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("revocation")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("revocation")
			}
			return err
		}
	}

	return nil
}

func (m *GetCertificateResponse) validateSeat(formats strfmt.Registry) error {
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

// ContextValidate validate this get certificate response based on the context it is used
func (m *GetCertificateResponse) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateAccount(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateProfile(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateRevocation(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateSeat(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *GetCertificateResponse) contextValidateAccount(ctx context.Context, formats strfmt.Registry) error {

	if m.Account != nil {
		if err := m.Account.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("account")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("account")
			}
			return err
		}
	}

	return nil
}

func (m *GetCertificateResponse) contextValidateProfile(ctx context.Context, formats strfmt.Registry) error {

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

func (m *GetCertificateResponse) contextValidateRevocation(ctx context.Context, formats strfmt.Registry) error {

	if m.Revocation != nil {
		if err := m.Revocation.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("revocation")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("revocation")
			}
			return err
		}
	}

	return nil
}

func (m *GetCertificateResponse) contextValidateSeat(ctx context.Context, formats strfmt.Registry) error {

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

// MarshalBinary interface implementation
func (m *GetCertificateResponse) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *GetCertificateResponse) UnmarshalBinary(b []byte) error {
	var res GetCertificateResponse
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
