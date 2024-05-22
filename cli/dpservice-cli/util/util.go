// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package util

var (
	BuildVersion string
)

func Must(err error) {
	if err != nil {
		panic(err)
	}
}
