// Code generated by go-swagger; DO NOT EDIT.

package cli

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"
	"fmt"

	"github.com/isometry/go-digicert-mpki/client/seat_management"

	"github.com/go-openapi/swag"
	"github.com/spf13/cobra"
)

// makeOperationSeatManagementDeleteSeatCmd returns a cmd to handle operation deleteSeat
func makeOperationSeatManagementDeleteSeatCmd() (*cobra.Command, error) {
	cmd := &cobra.Command{
		Use:   "deleteSeat",
		Short: ``,
		RunE:  runOperationSeatManagementDeleteSeat,
	}

	if err := registerOperationSeatManagementDeleteSeatParamFlags(cmd); err != nil {
		return nil, err
	}

	return cmd, nil
}

// runOperationSeatManagementDeleteSeat uses cmd flags to call endpoint api
func runOperationSeatManagementDeleteSeat(cmd *cobra.Command, args []string) error {
	appCli, err := makeClient(cmd, args)
	if err != nil {
		return err
	}
	// retrieve flag values from cmd and fill params
	params := seat_management.NewDeleteSeatParams()
	if err, _ := retrieveOperationSeatManagementDeleteSeatSeatIDFlag(params, "", cmd); err != nil {
		return err
	}
	if dryRun {

		logDebugf("dry-run flag specified. Skip sending request.")
		return nil
	}
	// make request and then print result
	msgStr, err := parseOperationSeatManagementDeleteSeatResult(appCli.SeatManagement.DeleteSeat(params))
	if err != nil {
		return err
	}
	if !debug {

		fmt.Println(msgStr)
	}
	return nil
}

// registerOperationSeatManagementDeleteSeatParamFlags registers all flags needed to fill params
func registerOperationSeatManagementDeleteSeatParamFlags(cmd *cobra.Command) error {
	if err := registerOperationSeatManagementDeleteSeatSeatIDParamFlags("", cmd); err != nil {
		return err
	}
	return nil
}

func registerOperationSeatManagementDeleteSeatSeatIDParamFlags(cmdPrefix string, cmd *cobra.Command) error {

	seatIdDescription := `Required. seatId`

	var seatIdFlagName string
	if cmdPrefix == "" {
		seatIdFlagName = "seatId"
	} else {
		seatIdFlagName = fmt.Sprintf("%v.seatId", cmdPrefix)
	}

	var seatIdFlagDefault string

	_ = cmd.PersistentFlags().String(seatIdFlagName, seatIdFlagDefault, seatIdDescription)

	return nil
}

func retrieveOperationSeatManagementDeleteSeatSeatIDFlag(m *seat_management.DeleteSeatParams, cmdPrefix string, cmd *cobra.Command) (error, bool) {
	retAdded := false
	if cmd.Flags().Changed("seatId") {

		var seatIdFlagName string
		if cmdPrefix == "" {
			seatIdFlagName = "seatId"
		} else {
			seatIdFlagName = fmt.Sprintf("%v.seatId", cmdPrefix)
		}

		seatIdFlagValue, err := cmd.Flags().GetString(seatIdFlagName)
		if err != nil {
			return err, false
		}
		m.SeatID = seatIdFlagValue

	}
	return nil, retAdded
}

// parseOperationSeatManagementDeleteSeatResult parses request result and return the string content
func parseOperationSeatManagementDeleteSeatResult(resp0 *seat_management.DeleteSeatOK, resp1 *seat_management.DeleteSeatNoContent, respErr error) (string, error) {
	if respErr != nil {

		var iResp0 interface{} = respErr
		resp0, ok := iResp0.(*seat_management.DeleteSeatOK)
		if ok {
			if !swag.IsZero(resp0) && !swag.IsZero(resp0.Payload) {
				msgStr, err := json.Marshal(resp0.Payload)
				if err != nil {
					return "", err
				}
				return string(msgStr), nil
			}
		}

		// Non schema case: warning deleteSeatNoContent is not supported

		// Non schema case: warning deleteSeatUnauthorized is not supported

		// Non schema case: warning deleteSeatForbidden is not supported

		return "", respErr
	}

	if !swag.IsZero(resp0) && !swag.IsZero(resp0.Payload) {
		msgStr, err := json.Marshal(resp0.Payload)
		if err != nil {
			return "", err
		}
		return string(msgStr), nil
	}

	// warning: non schema response deleteSeatNoContent is not supported by go-swagger cli yet.

	return "", nil
}