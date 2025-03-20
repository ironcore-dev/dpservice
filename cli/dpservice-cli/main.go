// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/ironcore-dev/dpservice/cli/dpservice-cli/cmd"
	"github.com/ironcore-dev/dpservice/cli/dpservice-cli/util"
	"github.com/ironcore-dev/dpservice/go/dpservice-go/errors"
)

var version = "unknown"

func main() {
	util.BuildVersion = version
	output := manualParseOutput()
	err := cmd.Command().Execute()
	if err != nil {
		//fmt.Println(cmd.Output)
		if strings.Contains(err.Error(), "Unimplemented desc") {
			err := cmd.RenderError(os.Stdout, fmt.Errorf("error in gRPC, client and server are probably using different proto version"), output)
			if err != nil {
				fmt.Printf("failed to render error: %v", err)
			}
			os.Exit(errors.SERVER_ERROR)
		}
		// check if it is Server side error
		if strings.Contains(err.Error(), "error code") {
			err := cmd.RenderError(os.Stdout, err, output)
			if err != nil {
				fmt.Printf("failed to render error: %v", err)
			}
			os.Exit(errors.SERVER_ERROR)
		}
		// else it is Client side error
		err := cmd.RenderError(os.Stdout, err, output)
		if err != nil {
			fmt.Printf("failed to render error: %v", err)
		}
		os.Exit(errors.CLIENT_ERROR)
	}
}

// manually parses output flag
// needed because if command execution fails, flags set inside command are not parsed
func manualParseOutput() string {
	args := os.Args[1:]

	for i := 0; i < len(args); i++ {
		if args[i] == "--output" || args[i] == "-o" {
			if i+1 < len(args) {
				return args[i+1]
			}
		} else if strings.HasPrefix(args[i], "--output=") {
			return strings.SplitN(args[i], "=", 2)[1]
		} else if strings.HasPrefix(args[i], "-o=") {
			return strings.SplitN(args[i], "=", 2)[1]
		}
	}
	return "name"
}
