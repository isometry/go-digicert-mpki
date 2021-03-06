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

// NewDeleteEnrollmentParams creates a new DeleteEnrollmentParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewDeleteEnrollmentParams() *DeleteEnrollmentParams {
	return &DeleteEnrollmentParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewDeleteEnrollmentParamsWithTimeout creates a new DeleteEnrollmentParams object
// with the ability to set a timeout on a request.
func NewDeleteEnrollmentParamsWithTimeout(timeout time.Duration) *DeleteEnrollmentParams {
	return &DeleteEnrollmentParams{
		timeout: timeout,
	}
}

// NewDeleteEnrollmentParamsWithContext creates a new DeleteEnrollmentParams object
// with the ability to set a context for a request.
func NewDeleteEnrollmentParamsWithContext(ctx context.Context) *DeleteEnrollmentParams {
	return &DeleteEnrollmentParams{
		Context: ctx,
	}
}

// NewDeleteEnrollmentParamsWithHTTPClient creates a new DeleteEnrollmentParams object
// with the ability to set a custom HTTPClient for a request.
func NewDeleteEnrollmentParamsWithHTTPClient(client *http.Client) *DeleteEnrollmentParams {
	return &DeleteEnrollmentParams{
		HTTPClient: client,
	}
}

/* DeleteEnrollmentParams contains all the parameters to send to the API endpoint
   for the delete enrollment operation.

   Typically these are written to a http.Request.
*/
type DeleteEnrollmentParams struct {

	/* DeleteEnrollRequest.

	   deleteEnrollRequest
	*/
	DeleteEnrollRequest *models.DeleteEnrollmentRequest

	/* EnrollCode.

	   enrollCode
	*/
	EnrollCode string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the delete enrollment params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *DeleteEnrollmentParams) WithDefaults() *DeleteEnrollmentParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the delete enrollment params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *DeleteEnrollmentParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the delete enrollment params
func (o *DeleteEnrollmentParams) WithTimeout(timeout time.Duration) *DeleteEnrollmentParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the delete enrollment params
func (o *DeleteEnrollmentParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the delete enrollment params
func (o *DeleteEnrollmentParams) WithContext(ctx context.Context) *DeleteEnrollmentParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the delete enrollment params
func (o *DeleteEnrollmentParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the delete enrollment params
func (o *DeleteEnrollmentParams) WithHTTPClient(client *http.Client) *DeleteEnrollmentParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the delete enrollment params
func (o *DeleteEnrollmentParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithDeleteEnrollRequest adds the deleteEnrollRequest to the delete enrollment params
func (o *DeleteEnrollmentParams) WithDeleteEnrollRequest(deleteEnrollRequest *models.DeleteEnrollmentRequest) *DeleteEnrollmentParams {
	o.SetDeleteEnrollRequest(deleteEnrollRequest)
	return o
}

// SetDeleteEnrollRequest adds the deleteEnrollRequest to the delete enrollment params
func (o *DeleteEnrollmentParams) SetDeleteEnrollRequest(deleteEnrollRequest *models.DeleteEnrollmentRequest) {
	o.DeleteEnrollRequest = deleteEnrollRequest
}

// WithEnrollCode adds the enrollCode to the delete enrollment params
func (o *DeleteEnrollmentParams) WithEnrollCode(enrollCode string) *DeleteEnrollmentParams {
	o.SetEnrollCode(enrollCode)
	return o
}

// SetEnrollCode adds the enrollCode to the delete enrollment params
func (o *DeleteEnrollmentParams) SetEnrollCode(enrollCode string) {
	o.EnrollCode = enrollCode
}

// WriteToRequest writes these params to a swagger request
func (o *DeleteEnrollmentParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.DeleteEnrollRequest != nil {
		if err := r.SetBodyParam(o.DeleteEnrollRequest); err != nil {
			return err
		}
	}

	// path param enrollCode
	if err := r.SetPathParam("enrollCode", o.EnrollCode); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
