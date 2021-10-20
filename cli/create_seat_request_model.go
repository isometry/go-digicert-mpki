// Code generated by go-swagger; DO NOT EDIT.

package cli

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/isometry/go-digicert-mpki/models"
	"github.com/spf13/cobra"
)

// Schema cli for CreateSeatRequest

// register flags to command
func registerModelCreateSeatRequestFlags(depth int, cmdPrefix string, cmd *cobra.Command) error {

	if err := registerCreateSeatRequestEmail(depth, cmdPrefix, cmd); err != nil {
		return err
	}

	if err := registerCreateSeatRequestPhone(depth, cmdPrefix, cmd); err != nil {
		return err
	}

	if err := registerCreateSeatRequestSeatID(depth, cmdPrefix, cmd); err != nil {
		return err
	}

	if err := registerCreateSeatRequestSeatName(depth, cmdPrefix, cmd); err != nil {
		return err
	}

	return nil
}

func registerCreateSeatRequestEmail(depth int, cmdPrefix string, cmd *cobra.Command) error {
	if depth > maxDepth {
		return nil
	}

	emailDescription := ``

	var emailFlagName string
	if cmdPrefix == "" {
		emailFlagName = "email"
	} else {
		emailFlagName = fmt.Sprintf("%v.email", cmdPrefix)
	}

	var emailFlagDefault string

	_ = cmd.PersistentFlags().String(emailFlagName, emailFlagDefault, emailDescription)

	return nil
}

func registerCreateSeatRequestPhone(depth int, cmdPrefix string, cmd *cobra.Command) error {
	if depth > maxDepth {
		return nil
	}

	phoneDescription := ``

	var phoneFlagName string
	if cmdPrefix == "" {
		phoneFlagName = "phone"
	} else {
		phoneFlagName = fmt.Sprintf("%v.phone", cmdPrefix)
	}

	var phoneFlagDefault string

	_ = cmd.PersistentFlags().String(phoneFlagName, phoneFlagDefault, phoneDescription)

	return nil
}

func registerCreateSeatRequestSeatID(depth int, cmdPrefix string, cmd *cobra.Command) error {
	if depth > maxDepth {
		return nil
	}

	seatIdDescription := ``

	var seatIdFlagName string
	if cmdPrefix == "" {
		seatIdFlagName = "seat_id"
	} else {
		seatIdFlagName = fmt.Sprintf("%v.seat_id", cmdPrefix)
	}

	var seatIdFlagDefault string

	_ = cmd.PersistentFlags().String(seatIdFlagName, seatIdFlagDefault, seatIdDescription)

	return nil
}

func registerCreateSeatRequestSeatName(depth int, cmdPrefix string, cmd *cobra.Command) error {
	if depth > maxDepth {
		return nil
	}

	seatNameDescription := ``

	var seatNameFlagName string
	if cmdPrefix == "" {
		seatNameFlagName = "seat_name"
	} else {
		seatNameFlagName = fmt.Sprintf("%v.seat_name", cmdPrefix)
	}

	var seatNameFlagDefault string

	_ = cmd.PersistentFlags().String(seatNameFlagName, seatNameFlagDefault, seatNameDescription)

	return nil
}

// retrieve flags from commands, and set value in model. Return true if any flag is passed by user to fill model field.
func retrieveModelCreateSeatRequestFlags(depth int, m *models.CreateSeatRequest, cmdPrefix string, cmd *cobra.Command) (error, bool) {
	retAdded := false

	err, emailAdded := retrieveCreateSeatRequestEmailFlags(depth, m, cmdPrefix, cmd)
	if err != nil {
		return err, false
	}
	retAdded = retAdded || emailAdded

	err, phoneAdded := retrieveCreateSeatRequestPhoneFlags(depth, m, cmdPrefix, cmd)
	if err != nil {
		return err, false
	}
	retAdded = retAdded || phoneAdded

	err, seatIdAdded := retrieveCreateSeatRequestSeatIDFlags(depth, m, cmdPrefix, cmd)
	if err != nil {
		return err, false
	}
	retAdded = retAdded || seatIdAdded

	err, seatNameAdded := retrieveCreateSeatRequestSeatNameFlags(depth, m, cmdPrefix, cmd)
	if err != nil {
		return err, false
	}
	retAdded = retAdded || seatNameAdded

	return nil, retAdded
}

func retrieveCreateSeatRequestEmailFlags(depth int, m *models.CreateSeatRequest, cmdPrefix string, cmd *cobra.Command) (error, bool) {
	if depth > maxDepth {
		return nil, false
	}
	retAdded := false

	emailFlagName := fmt.Sprintf("%v.email", cmdPrefix)
	if cmd.Flags().Changed(emailFlagName) {

		var emailFlagName string
		if cmdPrefix == "" {
			emailFlagName = "email"
		} else {
			emailFlagName = fmt.Sprintf("%v.email", cmdPrefix)
		}

		emailFlagValue, err := cmd.Flags().GetString(emailFlagName)
		if err != nil {
			return err, false
		}
		m.Email = emailFlagValue

		retAdded = true
	}

	return nil, retAdded
}

func retrieveCreateSeatRequestPhoneFlags(depth int, m *models.CreateSeatRequest, cmdPrefix string, cmd *cobra.Command) (error, bool) {
	if depth > maxDepth {
		return nil, false
	}
	retAdded := false

	phoneFlagName := fmt.Sprintf("%v.phone", cmdPrefix)
	if cmd.Flags().Changed(phoneFlagName) {

		var phoneFlagName string
		if cmdPrefix == "" {
			phoneFlagName = "phone"
		} else {
			phoneFlagName = fmt.Sprintf("%v.phone", cmdPrefix)
		}

		phoneFlagValue, err := cmd.Flags().GetString(phoneFlagName)
		if err != nil {
			return err, false
		}
		m.Phone = phoneFlagValue

		retAdded = true
	}

	return nil, retAdded
}

func retrieveCreateSeatRequestSeatIDFlags(depth int, m *models.CreateSeatRequest, cmdPrefix string, cmd *cobra.Command) (error, bool) {
	if depth > maxDepth {
		return nil, false
	}
	retAdded := false

	seatIdFlagName := fmt.Sprintf("%v.seat_id", cmdPrefix)
	if cmd.Flags().Changed(seatIdFlagName) {

		var seatIdFlagName string
		if cmdPrefix == "" {
			seatIdFlagName = "seat_id"
		} else {
			seatIdFlagName = fmt.Sprintf("%v.seat_id", cmdPrefix)
		}

		seatIdFlagValue, err := cmd.Flags().GetString(seatIdFlagName)
		if err != nil {
			return err, false
		}
		m.SeatID = seatIdFlagValue

		retAdded = true
	}

	return nil, retAdded
}

func retrieveCreateSeatRequestSeatNameFlags(depth int, m *models.CreateSeatRequest, cmdPrefix string, cmd *cobra.Command) (error, bool) {
	if depth > maxDepth {
		return nil, false
	}
	retAdded := false

	seatNameFlagName := fmt.Sprintf("%v.seat_name", cmdPrefix)
	if cmd.Flags().Changed(seatNameFlagName) {

		var seatNameFlagName string
		if cmdPrefix == "" {
			seatNameFlagName = "seat_name"
		} else {
			seatNameFlagName = fmt.Sprintf("%v.seat_name", cmdPrefix)
		}

		seatNameFlagValue, err := cmd.Flags().GetString(seatNameFlagName)
		if err != nil {
			return err, false
		}
		m.SeatName = seatNameFlagValue

		retAdded = true
	}

	return nil, retAdded
}