// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/ironcore-dev/dpservice-cli/cmd"
	"github.com/ironcore-dev/dpservice-cli/util"
	"github.com/ironcore-dev/dpservice-go/errors"
)

var version = "unknown"

func main() {
	util.BuildVersion = version
	if err := cmd.Command().Execute(); err != nil {
		if strings.Contains(err.Error(), "Unimplemented desc") {
			fmt.Println("Error in gRPC, client and server are probably using different proto version")
			os.Exit(errors.SERVER_ERROR)
		}
		// check if it is Server side error
		if err.Error() == strconv.Itoa(errors.SERVER_ERROR) || strings.Contains(err.Error(), "error code") {
			os.Exit(errors.SERVER_ERROR)
		}
		// else it is Client side error
		fmt.Fprintf(os.Stderr, "Error running command: %v\n", err)
		os.Exit(errors.CLIENT_ERROR)
	}
}
