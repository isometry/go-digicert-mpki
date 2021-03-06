// Code generated by go-swagger; DO NOT EDIT.

package certificate_enrollment

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/isometry/go-digicert-mpki/models"
)

// RecoverKeyReader is a Reader for the RecoverKey structure.
type RecoverKeyReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *RecoverKeyReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewRecoverKeyOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewRecoverKeyUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewRecoverKeyForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewRecoverKeyNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewRecoverKeyOK creates a RecoverKeyOK with default headers values
func NewRecoverKeyOK() *RecoverKeyOK {
	return &RecoverKeyOK{}
}

/* RecoverKeyOK describes a response with status code 200, with default header values.

OK
*/
type RecoverKeyOK struct {
	Payload models.Response
}

func (o *RecoverKeyOK) Error() string {
	return fmt.Sprintf("[GET /api/v1/certificate/{serialNumber}/key][%d] recoverKeyOK  %+v", 200, o.Payload)
}
func (o *RecoverKeyOK) GetPayload() models.Response {
	return o.Payload
}

func (o *RecoverKeyOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRecoverKeyUnauthorized creates a RecoverKeyUnauthorized with default headers values
func NewRecoverKeyUnauthorized() *RecoverKeyUnauthorized {
	return &RecoverKeyUnauthorized{}
}

/* RecoverKeyUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type RecoverKeyUnauthorized struct {
}

func (o *RecoverKeyUnauthorized) Error() string {
	return fmt.Sprintf("[GET /api/v1/certificate/{serialNumber}/key][%d] recoverKeyUnauthorized ", 401)
}

func (o *RecoverKeyUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewRecoverKeyForbidden creates a RecoverKeyForbidden with default headers values
func NewRecoverKeyForbidden() *RecoverKeyForbidden {
	return &RecoverKeyForbidden{}
}

/* RecoverKeyForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type RecoverKeyForbidden struct {
}

func (o *RecoverKeyForbidden) Error() string {
	return fmt.Sprintf("[GET /api/v1/certificate/{serialNumber}/key][%d] recoverKeyForbidden ", 403)
}

func (o *RecoverKeyForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewRecoverKeyNotFound creates a RecoverKeyNotFound with default headers values
func NewRecoverKeyNotFound() *RecoverKeyNotFound {
	return &RecoverKeyNotFound{}
}

/* RecoverKeyNotFound describes a response with status code 404, with default header values.

Not Found
*/
type RecoverKeyNotFound struct {
}

func (o *RecoverKeyNotFound) Error() string {
	return fmt.Sprintf("[GET /api/v1/certificate/{serialNumber}/key][%d] recoverKeyNotFound ", 404)
}

func (o *RecoverKeyNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}
