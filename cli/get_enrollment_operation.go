// Code generated by go-swagger; DO NOT EDIT.

package cli

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"
	"fmt"

	"github.com/isometry/go-digicert-mpki/client/user_management"

	"github.com/go-openapi/swag"
	"github.com/spf13/cobra"
)

// makeOperationUserManagementGetEnrollmentCmd returns a cmd to handle operation getEnrollment
func makeOperationUserManagementGetEnrollmentCmd() (*cobra.Command, error) {
	cmd := &cobra.Command{
		Use:   "getEnrollment",
		Short: ``,
		RunE:  runOperationUserManagementGetEnrollment,
	}

	if err := registerOperationUserManagementGetEnrollmentParamFlags(cmd); err != nil {
		return nil, err
	}

	return cmd, nil
}

// runOperationUserManagementGetEnrollment uses cmd flags to call endpoint api
func runOperationUserManagementGetEnrollment(cmd *cobra.Command, args []string) error {
	appCli, err := makeClient(cmd, args)
	if err != nil {
		return err
	}
	// retrieve flag values from cmd and fill params
	params := user_management.NewGetEnrollmentParams()
	if err, _ := retrieveOperationUserManagementGetEnrollmentEnrollCodeFlag(params, "", cmd); err != nil {
		return err
	}
	if err, _ := retrieveOperationUserManagementGetEnrollmentSeatIDFlag(params, "", cmd); err != nil {
		return err
	}
	if dryRun {

		logDebugf("dry-run flag specified. Skip sending request.")
		return nil
	}
	// make request and then print result
	msgStr, err := parseOperationUserManagementGetEnrollmentResult(appCli.UserManagement.GetEnrollment(params))
	if err != nil {
		return err
	}
	if !debug {

		fmt.Println(msgStr)
	}
	return nil
}

// registerOperationUserManagementGetEnrollmentParamFlags registers all flags needed to fill params
func registerOperationUserManagementGetEnrollmentParamFlags(cmd *cobra.Command) error {
	if err := registerOperationUserManagementGetEnrollmentEnrollCodeParamFlags("", cmd); err != nil {
		return err
	}
	if err := registerOperationUserManagementGetEnrollmentSeatIDParamFlags("", cmd); err != nil {
		return err
	}
	return nil
}

func registerOperationUserManagementGetEnrollmentEnrollCodeParamFlags(cmdPrefix string, cmd *cobra.Command) error {

	enrollCodeDescription := `Required. enrollCode`

	var enrollCodeFlagName string
	if cmdPrefix == "" {
		enrollCodeFlagName = "enrollCode"
	} else {
		enrollCodeFlagName = fmt.Sprintf("%v.enrollCode", cmdPrefix)
	}

	var enrollCodeFlagDefault string

	_ = cmd.PersistentFlags().String(enrollCodeFlagName, enrollCodeFlagDefault, enrollCodeDescription)

	return nil
}
func registerOperationUserManagementGetEnrollmentSeatIDParamFlags(cmdPrefix string, cmd *cobra.Command) error {

	seatIdDescription := `Required. seat_id`

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

func retrieveOperationUserManagementGetEnrollmentEnrollCodeFlag(m *user_management.GetEnrollmentParams, cmdPrefix string, cmd *cobra.Command) (error, bool) {
	retAdded := false
	if cmd.Flags().Changed("enrollCode") {

		var enrollCodeFlagName string
		if cmdPrefix == "" {
			enrollCodeFlagName = "enrollCode"
		} else {
			enrollCodeFlagName = fmt.Sprintf("%v.enrollCode", cmdPrefix)
		}

		enrollCodeFlagValue, err := cmd.Flags().GetString(enrollCodeFlagName)
		if err != nil {
			return err, false
		}
		m.EnrollCode = enrollCodeFlagValue

	}
	return nil, retAdded
}
func retrieveOperationUserManagementGetEnrollmentSeatIDFlag(m *user_management.GetEnrollmentParams, cmdPrefix string, cmd *cobra.Command) (error, bool) {
	retAdded := false
	if cmd.Flags().Changed("seat_id") {

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

	}
	return nil, retAdded
}

// parseOperationUserManagementGetEnrollmentResult parses request result and return the string content
func parseOperationUserManagementGetEnrollmentResult(resp0 *user_management.GetEnrollmentOK, respErr error) (string, error) {
	if respErr != nil {

		var iResp0 interface{} = respErr
		resp0, ok := iResp0.(*user_management.GetEnrollmentOK)
		if ok {
			if !swag.IsZero(resp0) && !swag.IsZero(resp0.Payload) {
				msgStr, err := json.Marshal(resp0.Payload)
				if err != nil {
					return "", err
				}
				return string(msgStr), nil
			}
		}

		// Non schema case: warning getEnrollmentUnauthorized is not supported

		// Non schema case: warning getEnrollmentForbidden is not supported

		// Non schema case: warning getEnrollmentNotFound is not supported

		return "", respErr
	}

	if !swag.IsZero(resp0) && !swag.IsZero(resp0.Payload) {
		msgStr, err := json.Marshal(resp0.Payload)
		if err != nil {
			return "", err
		}
		return string(msgStr), nil
	}

	return "", nil
}
