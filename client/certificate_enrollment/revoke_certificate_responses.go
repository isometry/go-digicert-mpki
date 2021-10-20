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

// RevokeCertificateReader is a Reader for the RevokeCertificate structure.
type RevokeCertificateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *RevokeCertificateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewRevokeCertificateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 201:
		result := NewRevokeCertificateCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewRevokeCertificateUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewRevokeCertificateForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewRevokeCertificateNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewRevokeCertificateOK creates a RevokeCertificateOK with default headers values
func NewRevokeCertificateOK() *RevokeCertificateOK {
	return &RevokeCertificateOK{}
}

/* RevokeCertificateOK describes a response with status code 200, with default header values.

OK
*/
type RevokeCertificateOK struct {
	Payload models.Response
}

func (o *RevokeCertificateOK) Error() string {
	return fmt.Sprintf("[PUT /api/v1/certificate/{serialNumber}/revoke][%d] revokeCertificateOK  %+v", 200, o.Payload)
}
func (o *RevokeCertificateOK) GetPayload() models.Response {
	return o.Payload
}

func (o *RevokeCertificateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRevokeCertificateCreated creates a RevokeCertificateCreated with default headers values
func NewRevokeCertificateCreated() *RevokeCertificateCreated {
	return &RevokeCertificateCreated{}
}

/* RevokeCertificateCreated describes a response with status code 201, with default header values.

Created
*/
type RevokeCertificateCreated struct {
}

func (o *RevokeCertificateCreated) Error() string {
	return fmt.Sprintf("[PUT /api/v1/certificate/{serialNumber}/revoke][%d] revokeCertificateCreated ", 201)
}

func (o *RevokeCertificateCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewRevokeCertificateUnauthorized creates a RevokeCertificateUnauthorized with default headers values
func NewRevokeCertificateUnauthorized() *RevokeCertificateUnauthorized {
	return &RevokeCertificateUnauthorized{}
}

/* RevokeCertificateUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type RevokeCertificateUnauthorized struct {
}

func (o *RevokeCertificateUnauthorized) Error() string {
	return fmt.Sprintf("[PUT /api/v1/certificate/{serialNumber}/revoke][%d] revokeCertificateUnauthorized ", 401)
}

func (o *RevokeCertificateUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewRevokeCertificateForbidden creates a RevokeCertificateForbidden with default headers values
func NewRevokeCertificateForbidden() *RevokeCertificateForbidden {
	return &RevokeCertificateForbidden{}
}

/* RevokeCertificateForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type RevokeCertificateForbidden struct {
}

func (o *RevokeCertificateForbidden) Error() string {
	return fmt.Sprintf("[PUT /api/v1/certificate/{serialNumber}/revoke][%d] revokeCertificateForbidden ", 403)
}

func (o *RevokeCertificateForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewRevokeCertificateNotFound creates a RevokeCertificateNotFound with default headers values
func NewRevokeCertificateNotFound() *RevokeCertificateNotFound {
	return &RevokeCertificateNotFound{}
}

/* RevokeCertificateNotFound describes a response with status code 404, with default header values.

Not Found
*/
type RevokeCertificateNotFound struct {
}

func (o *RevokeCertificateNotFound) Error() string {
	return fmt.Sprintf("[PUT /api/v1/certificate/{serialNumber}/revoke][%d] revokeCertificateNotFound ", 404)
}

func (o *RevokeCertificateNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}