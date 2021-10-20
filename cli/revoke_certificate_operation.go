// Code generated by go-swagger; DO NOT EDIT.

package cli

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"
	"fmt"

	"github.com/isometry/go-digicert-mpki/client/certificate_enrollment"
	"github.com/isometry/go-digicert-mpki/models"

	"github.com/go-openapi/swag"
	"github.com/spf13/cobra"
)

// makeOperationCertificateEnrollmentRevokeCertificateCmd returns a cmd to handle operation revokeCertificate
func makeOperationCertificateEnrollmentRevokeCertificateCmd() (*cobra.Command, error) {
	cmd := &cobra.Command{
		Use:   "revokeCertificate",
		Short: ``,
		RunE:  runOperationCertificateEnrollmentRevokeCertificate,
	}

	if err := registerOperationCertificateEnrollmentRevokeCertificateParamFlags(cmd); err != nil {
		return nil, err
	}

	return cmd, nil
}

// runOperationCertificateEnrollmentRevokeCertificate uses cmd flags to call endpoint api
func runOperationCertificateEnrollmentRevokeCertificate(cmd *cobra.Command, args []string) error {
	appCli, err := makeClient(cmd, args)
	if err != nil {
		return err
	}
	// retrieve flag values from cmd and fill params
	params := certificate_enrollment.NewRevokeCertificateParams()
	if err, _ := retrieveOperationCertificateEnrollmentRevokeCertificateRevokeCertificateRequestFlag(params, "", cmd); err != nil {
		return err
	}
	if err, _ := retrieveOperationCertificateEnrollmentRevokeCertificateSerialNumberFlag(params, "", cmd); err != nil {
		return err
	}
	if dryRun {

		logDebugf("dry-run flag specified. Skip sending request.")
		return nil
	}
	// make request and then print result
	msgStr, err := parseOperationCertificateEnrollmentRevokeCertificateResult(appCli.CertificateEnrollment.RevokeCertificate(params))
	if err != nil {
		return err
	}
	if !debug {

		fmt.Println(msgStr)
	}
	return nil
}

// registerOperationCertificateEnrollmentRevokeCertificateParamFlags registers all flags needed to fill params
func registerOperationCertificateEnrollmentRevokeCertificateParamFlags(cmd *cobra.Command) error {
	if err := registerOperationCertificateEnrollmentRevokeCertificateRevokeCertificateRequestParamFlags("", cmd); err != nil {
		return err
	}
	if err := registerOperationCertificateEnrollmentRevokeCertificateSerialNumberParamFlags("", cmd); err != nil {
		return err
	}
	return nil
}

func registerOperationCertificateEnrollmentRevokeCertificateRevokeCertificateRequestParamFlags(cmdPrefix string, cmd *cobra.Command) error {

	var revokeCertificateRequestFlagName string
	if cmdPrefix == "" {
		revokeCertificateRequestFlagName = "revokeCertificateRequest"
	} else {
		revokeCertificateRequestFlagName = fmt.Sprintf("%v.revokeCertificateRequest", cmdPrefix)
	}

	_ = cmd.PersistentFlags().String(revokeCertificateRequestFlagName, "", "Optional json string for [revokeCertificateRequest]. revokeCertificateRequest")

	// add flags for body
	if err := registerModelRevokeCertificateRequestFlags(0, "revokeCertificateRequest", cmd); err != nil {
		return err
	}

	return nil
}
func registerOperationCertificateEnrollmentRevokeCertificateSerialNumberParamFlags(cmdPrefix string, cmd *cobra.Command) error {

	serialNumberDescription := `Required. serialNumber`

	var serialNumberFlagName string
	if cmdPrefix == "" {
		serialNumberFlagName = "serialNumber"
	} else {
		serialNumberFlagName = fmt.Sprintf("%v.serialNumber", cmdPrefix)
	}

	var serialNumberFlagDefault string

	_ = cmd.PersistentFlags().String(serialNumberFlagName, serialNumberFlagDefault, serialNumberDescription)

	return nil
}

func retrieveOperationCertificateEnrollmentRevokeCertificateRevokeCertificateRequestFlag(m *certificate_enrollment.RevokeCertificateParams, cmdPrefix string, cmd *cobra.Command) (error, bool) {
	retAdded := false
	if cmd.Flags().Changed("revokeCertificateRequest") {
		// Read revokeCertificateRequest string from cmd and unmarshal
		revokeCertificateRequestValueStr, err := cmd.Flags().GetString("revokeCertificateRequest")
		if err != nil {
			return err, false
		}

		revokeCertificateRequestValue := models.RevokeCertificateRequest{}
		if err := json.Unmarshal([]byte(revokeCertificateRequestValueStr), &revokeCertificateRequestValue); err != nil {
			return fmt.Errorf("cannot unmarshal revokeCertificateRequest string in models.RevokeCertificateRequest: %v", err), false
		}
		m.RevokeCertificateRequest = &revokeCertificateRequestValue
	}
	revokeCertificateRequestValueModel := m.RevokeCertificateRequest
	if swag.IsZero(revokeCertificateRequestValueModel) {
		revokeCertificateRequestValueModel = &models.RevokeCertificateRequest{}
	}
	err, added := retrieveModelRevokeCertificateRequestFlags(0, revokeCertificateRequestValueModel, "revokeCertificateRequest", cmd)
	if err != nil {
		return err, false
	}
	if added {
		m.RevokeCertificateRequest = revokeCertificateRequestValueModel
	}
	if dryRun && debug {

		revokeCertificateRequestValueDebugBytes, err := json.Marshal(m.RevokeCertificateRequest)
		if err != nil {
			return err, false
		}
		logDebugf("RevokeCertificateRequest dry-run payload: %v", string(revokeCertificateRequestValueDebugBytes))
	}
	retAdded = retAdded || added

	return nil, retAdded
}
func retrieveOperationCertificateEnrollmentRevokeCertificateSerialNumberFlag(m *certificate_enrollment.RevokeCertificateParams, cmdPrefix string, cmd *cobra.Command) (error, bool) {
	retAdded := false
	if cmd.Flags().Changed("serialNumber") {

		var serialNumberFlagName string
		if cmdPrefix == "" {
			serialNumberFlagName = "serialNumber"
		} else {
			serialNumberFlagName = fmt.Sprintf("%v.serialNumber", cmdPrefix)
		}

		serialNumberFlagValue, err := cmd.Flags().GetString(serialNumberFlagName)
		if err != nil {
			return err, false
		}
		m.SerialNumber = serialNumberFlagValue

	}
	return nil, retAdded
}

// parseOperationCertificateEnrollmentRevokeCertificateResult parses request result and return the string content
func parseOperationCertificateEnrollmentRevokeCertificateResult(resp0 *certificate_enrollment.RevokeCertificateOK, resp1 *certificate_enrollment.RevokeCertificateCreated, respErr error) (string, error) {
	if respErr != nil {

		var iResp0 interface{} = respErr
		resp0, ok := iResp0.(*certificate_enrollment.RevokeCertificateOK)
		if ok {
			if !swag.IsZero(resp0) && !swag.IsZero(resp0.Payload) {
				msgStr, err := json.Marshal(resp0.Payload)
				if err != nil {
					return "", err
				}
				return string(msgStr), nil
			}
		}

		// Non schema case: warning revokeCertificateCreated is not supported

		// Non schema case: warning revokeCertificateUnauthorized is not supported

		// Non schema case: warning revokeCertificateForbidden is not supported

		// Non schema case: warning revokeCertificateNotFound is not supported

		return "", respErr
	}

	if !swag.IsZero(resp0) && !swag.IsZero(resp0.Payload) {
		msgStr, err := json.Marshal(resp0.Payload)
		if err != nil {
			return "", err
		}
		return string(msgStr), nil
	}

	// warning: non schema response revokeCertificateCreated is not supported by go-swagger cli yet.

	return "", nil
}