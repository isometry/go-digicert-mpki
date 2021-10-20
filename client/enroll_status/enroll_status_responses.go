// Code generated by go-swagger; DO NOT EDIT.

package enroll_status

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/isometry/go-digicert-mpki/models"
)

// EnrollStatusReader is a Reader for the EnrollStatus structure.
type EnrollStatusReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *EnrollStatusReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewEnrollStatusOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewEnrollStatusBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewEnrollStatusUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewEnrollStatusForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewEnrollStatusNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewEnrollStatusInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewEnrollStatusOK creates a EnrollStatusOK with default headers values
func NewEnrollStatusOK() *EnrollStatusOK {
	return &EnrollStatusOK{}
}

/* EnrollStatusOK describes a response with status code 200, with default header values.

Certificate enrollment status result
*/
type EnrollStatusOK struct {
	Payload []*models.GetEnrollStatusResponse
}

func (o *EnrollStatusOK) Error() string {
	return fmt.Sprintf("[GET /api/v1/enrollstatus/{seatId}][%d] enrollStatusOK  %+v", 200, o.Payload)
}
func (o *EnrollStatusOK) GetPayload() []*models.GetEnrollStatusResponse {
	return o.Payload
}

func (o *EnrollStatusOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewEnrollStatusBadRequest creates a EnrollStatusBadRequest with default headers values
func NewEnrollStatusBadRequest() *EnrollStatusBadRequest {
	return &EnrollStatusBadRequest{}
}

/* EnrollStatusBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type EnrollStatusBadRequest struct {
	Payload *models.ErrorResponse
}

func (o *EnrollStatusBadRequest) Error() string {
	return fmt.Sprintf("[GET /api/v1/enrollstatus/{seatId}][%d] enrollStatusBadRequest  %+v", 400, o.Payload)
}
func (o *EnrollStatusBadRequest) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *EnrollStatusBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewEnrollStatusUnauthorized creates a EnrollStatusUnauthorized with default headers values
func NewEnrollStatusUnauthorized() *EnrollStatusUnauthorized {
	return &EnrollStatusUnauthorized{}
}

/* EnrollStatusUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type EnrollStatusUnauthorized struct {
}

func (o *EnrollStatusUnauthorized) Error() string {
	return fmt.Sprintf("[GET /api/v1/enrollstatus/{seatId}][%d] enrollStatusUnauthorized ", 401)
}

func (o *EnrollStatusUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewEnrollStatusForbidden creates a EnrollStatusForbidden with default headers values
func NewEnrollStatusForbidden() *EnrollStatusForbidden {
	return &EnrollStatusForbidden{}
}

/* EnrollStatusForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type EnrollStatusForbidden struct {
}

func (o *EnrollStatusForbidden) Error() string {
	return fmt.Sprintf("[GET /api/v1/enrollstatus/{seatId}][%d] enrollStatusForbidden ", 403)
}

func (o *EnrollStatusForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewEnrollStatusNotFound creates a EnrollStatusNotFound with default headers values
func NewEnrollStatusNotFound() *EnrollStatusNotFound {
	return &EnrollStatusNotFound{}
}

/* EnrollStatusNotFound describes a response with status code 404, with default header values.

Not Found
*/
type EnrollStatusNotFound struct {
	Payload *models.ErrorResponse
}

func (o *EnrollStatusNotFound) Error() string {
	return fmt.Sprintf("[GET /api/v1/enrollstatus/{seatId}][%d] enrollStatusNotFound  %+v", 404, o.Payload)
}
func (o *EnrollStatusNotFound) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *EnrollStatusNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewEnrollStatusInternalServerError creates a EnrollStatusInternalServerError with default headers values
func NewEnrollStatusInternalServerError() *EnrollStatusInternalServerError {
	return &EnrollStatusInternalServerError{}
}

/* EnrollStatusInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type EnrollStatusInternalServerError struct {
	Payload *models.ErrorResponse
}

func (o *EnrollStatusInternalServerError) Error() string {
	return fmt.Sprintf("[GET /api/v1/enrollstatus/{seatId}][%d] enrollStatusInternalServerError  %+v", 500, o.Payload)
}
func (o *EnrollStatusInternalServerError) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *EnrollStatusInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
