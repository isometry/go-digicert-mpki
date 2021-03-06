// Code generated by go-swagger; DO NOT EDIT.

package certificate_enrollment

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// New creates a new certificate enrollment API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

/*
Client for certificate enrollment API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientOption is the option for Client methods
type ClientOption func(*runtime.ClientOperation)

// ClientService is the interface for Client methods
type ClientService interface {
	EnrollCertificate(params *EnrollCertificateParams, opts ...ClientOption) (*EnrollCertificateOK, *EnrollCertificateCreated, error)

	GetCertificate(params *GetCertificateParams, opts ...ClientOption) (*GetCertificateOK, error)

	RecoverKey(params *RecoverKeyParams, opts ...ClientOption) (*RecoverKeyOK, error)

	RenewCertificate(params *RenewCertificateParams, opts ...ClientOption) (*RenewCertificateOK, *RenewCertificateCreated, error)

	RevokeCertificate(params *RevokeCertificateParams, opts ...ClientOption) (*RevokeCertificateOK, *RevokeCertificateCreated, error)

	UnRevokeCertificate(params *UnRevokeCertificateParams, opts ...ClientOption) (*UnRevokeCertificateOK, *UnRevokeCertificateNoContent, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
  EnrollCertificate this API is used to enroll a certificate for a given profile
*/
func (a *Client) EnrollCertificate(params *EnrollCertificateParams, opts ...ClientOption) (*EnrollCertificateOK, *EnrollCertificateCreated, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewEnrollCertificateParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "enrollCertificate",
		Method:             "POST",
		PathPattern:        "/api/v1/certificate",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &EnrollCertificateReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, nil, err
	}
	switch value := result.(type) {
	case *EnrollCertificateOK:
		return value, nil, nil
	case *EnrollCertificateCreated:
		return nil, value, nil
	}
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for certificate_enrollment: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  GetCertificate this API is used to get certificate details for a given certificate serial number
*/
func (a *Client) GetCertificate(params *GetCertificateParams, opts ...ClientOption) (*GetCertificateOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetCertificateParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "getCertificate",
		Method:             "GET",
		PathPattern:        "/api/v1/certificate/{serialNumber}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetCertificateReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*GetCertificateOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for getCertificate: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  RecoverKey this API is used to get private key information for key escrowed certificate with given serial number
*/
func (a *Client) RecoverKey(params *RecoverKeyParams, opts ...ClientOption) (*RecoverKeyOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewRecoverKeyParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "recoverKey",
		Method:             "GET",
		PathPattern:        "/api/v1/certificate/{serialNumber}/key",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &RecoverKeyReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*RecoverKeyOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for recoverKey: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  RenewCertificate this API is used to renew certificate with the given serial number
*/
func (a *Client) RenewCertificate(params *RenewCertificateParams, opts ...ClientOption) (*RenewCertificateOK, *RenewCertificateCreated, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewRenewCertificateParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "renewCertificate",
		Method:             "POST",
		PathPattern:        "/api/v1/certificate/{serialNumber}/renew",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &RenewCertificateReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, nil, err
	}
	switch value := result.(type) {
	case *RenewCertificateOK:
		return value, nil, nil
	case *RenewCertificateCreated:
		return nil, value, nil
	}
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for certificate_enrollment: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  RevokeCertificate this API can revoke certificate with the given serial number
*/
func (a *Client) RevokeCertificate(params *RevokeCertificateParams, opts ...ClientOption) (*RevokeCertificateOK, *RevokeCertificateCreated, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewRevokeCertificateParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "revokeCertificate",
		Method:             "PUT",
		PathPattern:        "/api/v1/certificate/{serialNumber}/revoke",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &RevokeCertificateReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, nil, err
	}
	switch value := result.(type) {
	case *RevokeCertificateOK:
		return value, nil, nil
	case *RevokeCertificateCreated:
		return nil, value, nil
	}
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for certificate_enrollment: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  UnRevokeCertificate this API can resume certificate with the given serial number
*/
func (a *Client) UnRevokeCertificate(params *UnRevokeCertificateParams, opts ...ClientOption) (*UnRevokeCertificateOK, *UnRevokeCertificateNoContent, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewUnRevokeCertificateParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "unRevokeCertificate",
		Method:             "DELETE",
		PathPattern:        "/api/v1/certificate/{serialNumber}/revoke",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &UnRevokeCertificateReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, nil, err
	}
	switch value := result.(type) {
	case *UnRevokeCertificateOK:
		return value, nil, nil
	case *UnRevokeCertificateNoContent:
		return nil, value, nil
	}
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for certificate_enrollment: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
