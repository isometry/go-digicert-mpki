// Code generated by go-swagger; DO NOT EDIT.

package user_management

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/isometry/go-digicert-mpki/models"
)

// GetEnrollmentReader is a Reader for the GetEnrollment structure.
type GetEnrollmentReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetEnrollmentReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetEnrollmentOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewGetEnrollmentUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetEnrollmentForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetEnrollmentNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewGetEnrollmentOK creates a GetEnrollmentOK with default headers values
func NewGetEnrollmentOK() *GetEnrollmentOK {
	return &GetEnrollmentOK{}
}

/* GetEnrollmentOK describes a response with status code 200, with default header values.

OK
*/
type GetEnrollmentOK struct {
	Payload models.Response
}

func (o *GetEnrollmentOK) Error() string {
	return fmt.Sprintf("[GET /api/v1/enrollment/{enrollCode}][%d] getEnrollmentOK  %+v", 200, o.Payload)
}
func (o *GetEnrollmentOK) GetPayload() models.Response {
	return o.Payload
}

func (o *GetEnrollmentOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetEnrollmentUnauthorized creates a GetEnrollmentUnauthorized with default headers values
func NewGetEnrollmentUnauthorized() *GetEnrollmentUnauthorized {
	return &GetEnrollmentUnauthorized{}
}

/* GetEnrollmentUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type GetEnrollmentUnauthorized struct {
}

func (o *GetEnrollmentUnauthorized) Error() string {
	return fmt.Sprintf("[GET /api/v1/enrollment/{enrollCode}][%d] getEnrollmentUnauthorized ", 401)
}

func (o *GetEnrollmentUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewGetEnrollmentForbidden creates a GetEnrollmentForbidden with default headers values
func NewGetEnrollmentForbidden() *GetEnrollmentForbidden {
	return &GetEnrollmentForbidden{}
}

/* GetEnrollmentForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type GetEnrollmentForbidden struct {
}

func (o *GetEnrollmentForbidden) Error() string {
	return fmt.Sprintf("[GET /api/v1/enrollment/{enrollCode}][%d] getEnrollmentForbidden ", 403)
}

func (o *GetEnrollmentForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewGetEnrollmentNotFound creates a GetEnrollmentNotFound with default headers values
func NewGetEnrollmentNotFound() *GetEnrollmentNotFound {
	return &GetEnrollmentNotFound{}
}

/* GetEnrollmentNotFound describes a response with status code 404, with default header values.

Not Found
*/
type GetEnrollmentNotFound struct {
}

func (o *GetEnrollmentNotFound) Error() string {
	return fmt.Sprintf("[GET /api/v1/enrollment/{enrollCode}][%d] getEnrollmentNotFound ", 404)
}

func (o *GetEnrollmentNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}
