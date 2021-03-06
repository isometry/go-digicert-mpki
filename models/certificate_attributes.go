// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"strconv"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// CertificateAttributes CertificateAttributes
//
// swagger:model CertificateAttributes
type CertificateAttributes struct {

	// common name
	CommonName string `json:"common_name,omitempty"`

	// content type
	ContentType string `json:"content_type,omitempty"`

	// counter signature
	CounterSignature string `json:"counter_signature,omitempty"`

	// country
	Country string `json:"country,omitempty"`

	// custom attributes
	CustomAttributes map[string]string `json:"custom_attributes,omitempty"`

	// dn qualifier
	DnQualifier string `json:"dn_qualifier,omitempty"`

	// domain component
	DomainComponent []*Attribute `json:"domain_component"`

	// domain name
	DomainName string `json:"domain_name,omitempty"`

	// email
	Email string `json:"email,omitempty"`

	// given name
	GivenName string `json:"given_name,omitempty"`

	// ip address
	IPAddress string `json:"ip_address,omitempty"`

	// job title
	JobTitle string `json:"job_title,omitempty"`

	// locality
	Locality string `json:"locality,omitempty"`

	// message digest
	MessageDigest string `json:"message_digest,omitempty"`

	// organization name
	OrganizationName string `json:"organization_name,omitempty"`

	// organization unit
	OrganizationUnit []*Attribute `json:"organization_unit"`

	// postal code
	PostalCode string `json:"postal_code,omitempty"`

	// pseudonym
	Pseudonym string `json:"pseudonym,omitempty"`

	// san
	San *SanAttributes `json:"san,omitempty"`

	// serial number
	SerialNumber string `json:"serial_number,omitempty"`

	// signing time
	SigningTime string `json:"signing_time,omitempty"`

	// state
	State string `json:"state,omitempty"`

	// street address
	StreetAddress []*Attribute `json:"street_address"`

	// surname
	Surname string `json:"surname,omitempty"`

	// unique identifier
	UniqueIdentifier string `json:"unique_identifier,omitempty"`

	// unstructured address
	UnstructuredAddress string `json:"unstructured_address,omitempty"`

	// unstructured name
	UnstructuredName string `json:"unstructured_name,omitempty"`

	// user id
	UserID string `json:"user_id,omitempty"`
}

// Validate validates this certificate attributes
func (m *CertificateAttributes) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateDomainComponent(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateOrganizationUnit(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSan(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateStreetAddress(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *CertificateAttributes) validateDomainComponent(formats strfmt.Registry) error {
	if swag.IsZero(m.DomainComponent) { // not required
		return nil
	}

	for i := 0; i < len(m.DomainComponent); i++ {
		if swag.IsZero(m.DomainComponent[i]) { // not required
			continue
		}

		if m.DomainComponent[i] != nil {
			if err := m.DomainComponent[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("domain_component" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("domain_component" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *CertificateAttributes) validateOrganizationUnit(formats strfmt.Registry) error {
	if swag.IsZero(m.OrganizationUnit) { // not required
		return nil
	}

	for i := 0; i < len(m.OrganizationUnit); i++ {
		if swag.IsZero(m.OrganizationUnit[i]) { // not required
			continue
		}

		if m.OrganizationUnit[i] != nil {
			if err := m.OrganizationUnit[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("organization_unit" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("organization_unit" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *CertificateAttributes) validateSan(formats strfmt.Registry) error {
	if swag.IsZero(m.San) { // not required
		return nil
	}

	if m.San != nil {
		if err := m.San.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("san")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("san")
			}
			return err
		}
	}

	return nil
}

func (m *CertificateAttributes) validateStreetAddress(formats strfmt.Registry) error {
	if swag.IsZero(m.StreetAddress) { // not required
		return nil
	}

	for i := 0; i < len(m.StreetAddress); i++ {
		if swag.IsZero(m.StreetAddress[i]) { // not required
			continue
		}

		if m.StreetAddress[i] != nil {
			if err := m.StreetAddress[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("street_address" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("street_address" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// ContextValidate validate this certificate attributes based on the context it is used
func (m *CertificateAttributes) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateDomainComponent(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateOrganizationUnit(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateSan(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateStreetAddress(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *CertificateAttributes) contextValidateDomainComponent(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.DomainComponent); i++ {

		if m.DomainComponent[i] != nil {
			if err := m.DomainComponent[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("domain_component" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("domain_component" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *CertificateAttributes) contextValidateOrganizationUnit(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.OrganizationUnit); i++ {

		if m.OrganizationUnit[i] != nil {
			if err := m.OrganizationUnit[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("organization_unit" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("organization_unit" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *CertificateAttributes) contextValidateSan(ctx context.Context, formats strfmt.Registry) error {

	if m.San != nil {
		if err := m.San.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("san")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("san")
			}
			return err
		}
	}

	return nil
}

func (m *CertificateAttributes) contextValidateStreetAddress(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.StreetAddress); i++ {

		if m.StreetAddress[i] != nil {
			if err := m.StreetAddress[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("street_address" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("street_address" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *CertificateAttributes) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *CertificateAttributes) UnmarshalBinary(b []byte) error {
	var res CertificateAttributes
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
