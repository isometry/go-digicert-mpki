// Code generated by go-swagger; DO NOT EDIT.

package seat_management

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/isometry/go-digicert-mpki/models"
)

// DeleteSeatReader is a Reader for the DeleteSeat structure.
type DeleteSeatReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *DeleteSeatReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewDeleteSeatOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 204:
		result := NewDeleteSeatNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewDeleteSeatUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewDeleteSeatForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewDeleteSeatOK creates a DeleteSeatOK with default headers values
func NewDeleteSeatOK() *DeleteSeatOK {
	return &DeleteSeatOK{}
}

/* DeleteSeatOK describes a response with status code 200, with default header values.

OK
*/
type DeleteSeatOK struct {
	Payload models.Response
}

func (o *DeleteSeatOK) Error() string {
	return fmt.Sprintf("[DELETE /api/v1/seat/{seatId}][%d] deleteSeatOK  %+v", 200, o.Payload)
}
func (o *DeleteSeatOK) GetPayload() models.Response {
	return o.Payload
}

func (o *DeleteSeatOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteSeatNoContent creates a DeleteSeatNoContent with default headers values
func NewDeleteSeatNoContent() *DeleteSeatNoContent {
	return &DeleteSeatNoContent{}
}

/* DeleteSeatNoContent describes a response with status code 204, with default header values.

No Content
*/
type DeleteSeatNoContent struct {
}

func (o *DeleteSeatNoContent) Error() string {
	return fmt.Sprintf("[DELETE /api/v1/seat/{seatId}][%d] deleteSeatNoContent ", 204)
}

func (o *DeleteSeatNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewDeleteSeatUnauthorized creates a DeleteSeatUnauthorized with default headers values
func NewDeleteSeatUnauthorized() *DeleteSeatUnauthorized {
	return &DeleteSeatUnauthorized{}
}

/* DeleteSeatUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type DeleteSeatUnauthorized struct {
}

func (o *DeleteSeatUnauthorized) Error() string {
	return fmt.Sprintf("[DELETE /api/v1/seat/{seatId}][%d] deleteSeatUnauthorized ", 401)
}

func (o *DeleteSeatUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewDeleteSeatForbidden creates a DeleteSeatForbidden with default headers values
func NewDeleteSeatForbidden() *DeleteSeatForbidden {
	return &DeleteSeatForbidden{}
}

/* DeleteSeatForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type DeleteSeatForbidden struct {
}

func (o *DeleteSeatForbidden) Error() string {
	return fmt.Sprintf("[DELETE /api/v1/seat/{seatId}][%d] deleteSeatForbidden ", 403)
}

func (o *DeleteSeatForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}
