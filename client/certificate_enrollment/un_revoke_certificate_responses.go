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

// UnRevokeCertificateReader is a Reader for the UnRevokeCertificate structure.
type UnRevokeCertificateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *UnRevokeCertificateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewUnRevokeCertificateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 204:
		result := NewUnRevokeCertificateNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewUnRevokeCertificateUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewUnRevokeCertificateForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewUnRevokeCertificateOK creates a UnRevokeCertificateOK with default headers values
func NewUnRevokeCertificateOK() *UnRevokeCertificateOK {
	return &UnRevokeCertificateOK{}
}

/* UnRevokeCertificateOK describes a response with status code 200, with default header values.

OK
*/
type UnRevokeCertificateOK struct {
	Payload models.Response
}

func (o *UnRevokeCertificateOK) Error() string {
	return fmt.Sprintf("[DELETE /api/v1/certificate/{serialNumber}/revoke][%d] unRevokeCertificateOK  %+v", 200, o.Payload)
}
func (o *UnRevokeCertificateOK) GetPayload() models.Response {
	return o.Payload
}

func (o *UnRevokeCertificateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUnRevokeCertificateNoContent creates a UnRevokeCertificateNoContent with default headers values
func NewUnRevokeCertificateNoContent() *UnRevokeCertificateNoContent {
	return &UnRevokeCertificateNoContent{}
}

/* UnRevokeCertificateNoContent describes a response with status code 204, with default header values.

No Content
*/
type UnRevokeCertificateNoContent struct {
}

func (o *UnRevokeCertificateNoContent) Error() string {
	return fmt.Sprintf("[DELETE /api/v1/certificate/{serialNumber}/revoke][%d] unRevokeCertificateNoContent ", 204)
}

func (o *UnRevokeCertificateNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewUnRevokeCertificateUnauthorized creates a UnRevokeCertificateUnauthorized with default headers values
func NewUnRevokeCertificateUnauthorized() *UnRevokeCertificateUnauthorized {
	return &UnRevokeCertificateUnauthorized{}
}

/* UnRevokeCertificateUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type UnRevokeCertificateUnauthorized struct {
}

func (o *UnRevokeCertificateUnauthorized) Error() string {
	return fmt.Sprintf("[DELETE /api/v1/certificate/{serialNumber}/revoke][%d] unRevokeCertificateUnauthorized ", 401)
}

func (o *UnRevokeCertificateUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewUnRevokeCertificateForbidden creates a UnRevokeCertificateForbidden with default headers values
func NewUnRevokeCertificateForbidden() *UnRevokeCertificateForbidden {
	return &UnRevokeCertificateForbidden{}
}

/* UnRevokeCertificateForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type UnRevokeCertificateForbidden struct {
}

func (o *UnRevokeCertificateForbidden) Error() string {
	return fmt.Sprintf("[DELETE /api/v1/certificate/{serialNumber}/revoke][%d] unRevokeCertificateForbidden ", 403)
}

func (o *UnRevokeCertificateForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}