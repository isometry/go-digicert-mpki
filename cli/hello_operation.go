// Code generated by go-swagger; DO NOT EDIT.

package cli

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"
	"fmt"

	"github.com/isometry/go-digicert-mpki/client/hello"

	"github.com/go-openapi/swag"
	"github.com/spf13/cobra"
)

// makeOperationHelloHelloCmd returns a cmd to handle operation hello
func makeOperationHelloHelloCmd() (*cobra.Command, error) {
	cmd := &cobra.Command{
		Use:   "hello",
		Short: ``,
		RunE:  runOperationHelloHello,
	}

	if err := registerOperationHelloHelloParamFlags(cmd); err != nil {
		return nil, err
	}

	return cmd, nil
}

// runOperationHelloHello uses cmd flags to call endpoint api
func runOperationHelloHello(cmd *cobra.Command, args []string) error {
	appCli, err := makeClient(cmd, args)
	if err != nil {
		return err
	}
	// retrieve flag values from cmd and fill params
	params := hello.NewHelloParams()
	if dryRun {

		logDebugf("dry-run flag specified. Skip sending request.")
		return nil
	}
	// make request and then print result
	msgStr, err := parseOperationHelloHelloResult(appCli.Hello.Hello(params))
	if err != nil {
		return err
	}
	if !debug {

		fmt.Println(msgStr)
	}
	return nil
}

// registerOperationHelloHelloParamFlags registers all flags needed to fill params
func registerOperationHelloHelloParamFlags(cmd *cobra.Command) error {
	return nil
}

// parseOperationHelloHelloResult parses request result and return the string content
func parseOperationHelloHelloResult(resp0 *hello.HelloOK, respErr error) (string, error) {
	if respErr != nil {

		var iResp0 interface{} = respErr
		resp0, ok := iResp0.(*hello.HelloOK)
		if ok {
			if !swag.IsZero(resp0) && !swag.IsZero(resp0.Payload) {
				msgStr, err := json.Marshal(resp0.Payload)
				if err != nil {
					return "", err
				}
				return string(msgStr), nil
			}
		}

		// Non schema case: warning helloUnauthorized is not supported

		// Non schema case: warning helloForbidden is not supported

		// Non schema case: warning helloNotFound is not supported

		return "", respErr
	}

	if !swag.IsZero(resp0) && !swag.IsZero(resp0.Payload) {
		msgStr := fmt.Sprintf("%v", resp0.Payload)
		return string(msgStr), nil
	}

	return "", nil
}
