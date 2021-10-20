// Code generated by go-swagger; DO NOT EDIT.

package cli

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/swag"
	"github.com/isometry/go-digicert-mpki/models"

	"github.com/spf13/cobra"
)

// Schema cli for DeleteEnrollmentRequest

// register flags to command
func registerModelDeleteEnrollmentRequestFlags(depth int, cmdPrefix string, cmd *cobra.Command) error {

	if err := registerDeleteEnrollmentRequestSeat(depth, cmdPrefix, cmd); err != nil {
		return err
	}

	return nil
}

func registerDeleteEnrollmentRequestSeat(depth int, cmdPrefix string, cmd *cobra.Command) error {
	if depth > maxDepth {
		return nil
	}

	var seatFlagName string
	if cmdPrefix == "" {
		seatFlagName = "seat"
	} else {
		seatFlagName = fmt.Sprintf("%v.seat", cmdPrefix)
	}

	if err := registerModelSeatFlags(depth+1, seatFlagName, cmd); err != nil {
		return err
	}

	return nil
}

// retrieve flags from commands, and set value in model. Return true if any flag is passed by user to fill model field.
func retrieveModelDeleteEnrollmentRequestFlags(depth int, m *models.DeleteEnrollmentRequest, cmdPrefix string, cmd *cobra.Command) (error, bool) {
	retAdded := false

	err, seatAdded := retrieveDeleteEnrollmentRequestSeatFlags(depth, m, cmdPrefix, cmd)
	if err != nil {
		return err, false
	}
	retAdded = retAdded || seatAdded

	return nil, retAdded
}

func retrieveDeleteEnrollmentRequestSeatFlags(depth int, m *models.DeleteEnrollmentRequest, cmdPrefix string, cmd *cobra.Command) (error, bool) {
	if depth > maxDepth {
		return nil, false
	}
	retAdded := false

	seatFlagName := fmt.Sprintf("%v.seat", cmdPrefix)
	if cmd.Flags().Changed(seatFlagName) {
		// info: complex object seat Seat is retrieved outside this Changed() block
	}
	seatFlagValue := m.Seat
	if swag.IsZero(seatFlagValue) {
		seatFlagValue = &models.Seat{}
	}

	err, seatAdded := retrieveModelSeatFlags(depth+1, seatFlagValue, seatFlagName, cmd)
	if err != nil {
		return err, false
	}
	retAdded = retAdded || seatAdded
	if seatAdded {
		m.Seat = seatFlagValue
	}

	return nil, retAdded
}