// Code generated by go-swagger; DO NOT EDIT.

package user_management

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"net/http"
	"time"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	cr "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"

	"github.com/isometry/go-digicert-mpki/models"
)

// NewResetPasscodeParams creates a new ResetPasscodeParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewResetPasscodeParams() *ResetPasscodeParams {
	return &ResetPasscodeParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewResetPasscodeParamsWithTimeout creates a new ResetPasscodeParams object
// with the ability to set a timeout on a request.
func NewResetPasscodeParamsWithTimeout(timeout time.Duration) *ResetPasscodeParams {
	return &ResetPasscodeParams{
		timeout: timeout,
	}
}

// NewResetPasscodeParamsWithContext creates a new ResetPasscodeParams object
// with the ability to set a context for a request.
func NewResetPasscodeParamsWithContext(ctx context.Context) *ResetPasscodeParams {
	return &ResetPasscodeParams{
		Context: ctx,
	}
}

// NewResetPasscodeParamsWithHTTPClient creates a new ResetPasscodeParams object
// with the ability to set a custom HTTPClient for a request.
func NewResetPasscodeParamsWithHTTPClient(client *http.Client) *ResetPasscodeParams {
	return &ResetPasscodeParams{
		HTTPClient: client,
	}
}

/* ResetPasscodeParams contains all the parameters to send to the API endpoint
   for the reset passcode operation.

   Typically these are written to a http.Request.
*/
type ResetPasscodeParams struct {

	/* EnrollCode.

	   enrollCode
	*/
	EnrollCode string

	/* ResetPasscodeRequest.

	   resetPasscodeRequest
	*/
	ResetPasscodeRequest *models.ResetPasscodeRequest

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the reset passcode params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ResetPasscodeParams) WithDefaults() *ResetPasscodeParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the reset passcode params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ResetPasscodeParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the reset passcode params
func (o *ResetPasscodeParams) WithTimeout(timeout time.Duration) *ResetPasscodeParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the reset passcode params
func (o *ResetPasscodeParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the reset passcode params
func (o *ResetPasscodeParams) WithContext(ctx context.Context) *ResetPasscodeParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the reset passcode params
func (o *ResetPasscodeParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the reset passcode params
func (o *ResetPasscodeParams) WithHTTPClient(client *http.Client) *ResetPasscodeParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the reset passcode params
func (o *ResetPasscodeParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithEnrollCode adds the enrollCode to the reset passcode params
func (o *ResetPasscodeParams) WithEnrollCode(enrollCode string) *ResetPasscodeParams {
	o.SetEnrollCode(enrollCode)
	return o
}

// SetEnrollCode adds the enrollCode to the reset passcode params
func (o *ResetPasscodeParams) SetEnrollCode(enrollCode string) {
	o.EnrollCode = enrollCode
}

// WithResetPasscodeRequest adds the resetPasscodeRequest to the reset passcode params
func (o *ResetPasscodeParams) WithResetPasscodeRequest(resetPasscodeRequest *models.ResetPasscodeRequest) *ResetPasscodeParams {
	o.SetResetPasscodeRequest(resetPasscodeRequest)
	return o
}

// SetResetPasscodeRequest adds the resetPasscodeRequest to the reset passcode params
func (o *ResetPasscodeParams) SetResetPasscodeRequest(resetPasscodeRequest *models.ResetPasscodeRequest) {
	o.ResetPasscodeRequest = resetPasscodeRequest
}

// WriteToRequest writes these params to a swagger request
func (o *ResetPasscodeParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param enrollCode
	if err := r.SetPathParam("enrollCode", o.EnrollCode); err != nil {
		return err
	}
	if o.ResetPasscodeRequest != nil {
		if err := r.SetBodyParam(o.ResetPasscodeRequest); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
