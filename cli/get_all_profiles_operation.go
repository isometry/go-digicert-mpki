// Code generated by go-swagger; DO NOT EDIT.

package cli

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"
	"fmt"

	"github.com/isometry/go-digicert-mpki/client/certificate_profile"

	"github.com/go-openapi/swag"
	"github.com/spf13/cobra"
)

// makeOperationCertificateProfileGetAllProfilesCmd returns a cmd to handle operation getAllProfiles
func makeOperationCertificateProfileGetAllProfilesCmd() (*cobra.Command, error) {
	cmd := &cobra.Command{
		Use:   "getAllProfiles",
		Short: ``,
		RunE:  runOperationCertificateProfileGetAllProfiles,
	}

	if err := registerOperationCertificateProfileGetAllProfilesParamFlags(cmd); err != nil {
		return nil, err
	}

	return cmd, nil
}

// runOperationCertificateProfileGetAllProfiles uses cmd flags to call endpoint api
func runOperationCertificateProfileGetAllProfiles(cmd *cobra.Command, args []string) error {
	appCli, err := makeClient(cmd, args)
	if err != nil {
		return err
	}
	// retrieve flag values from cmd and fill params
	params := certificate_profile.NewGetAllProfilesParams()
	if dryRun {

		logDebugf("dry-run flag specified. Skip sending request.")
		return nil
	}
	// make request and then print result
	msgStr, err := parseOperationCertificateProfileGetAllProfilesResult(appCli.CertificateProfile.GetAllProfiles(params))
	if err != nil {
		return err
	}
	if !debug {

		fmt.Println(msgStr)
	}
	return nil
}

// registerOperationCertificateProfileGetAllProfilesParamFlags registers all flags needed to fill params
func registerOperationCertificateProfileGetAllProfilesParamFlags(cmd *cobra.Command) error {
	return nil
}

// parseOperationCertificateProfileGetAllProfilesResult parses request result and return the string content
func parseOperationCertificateProfileGetAllProfilesResult(resp0 *certificate_profile.GetAllProfilesOK, respErr error) (string, error) {
	if respErr != nil {

		var iResp0 interface{} = respErr
		resp0, ok := iResp0.(*certificate_profile.GetAllProfilesOK)
		if ok {
			if !swag.IsZero(resp0) && !swag.IsZero(resp0.Payload) {
				msgStr, err := json.Marshal(resp0.Payload)
				if err != nil {
					return "", err
				}
				return string(msgStr), nil
			}
		}

		// Non schema case: warning getAllProfilesUnauthorized is not supported

		// Non schema case: warning getAllProfilesForbidden is not supported

		// Non schema case: warning getAllProfilesNotFound is not supported

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
