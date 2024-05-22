// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package flag

import (
	"net/netip"
	"strings"

	"github.com/spf13/pflag"
)

type prefixValue netip.Prefix

func newPrefixValue(val netip.Prefix, p *netip.Prefix) *prefixValue {
	*p = val
	return (*prefixValue)(p)
}

func (v *prefixValue) String() string {
	return netip.Prefix(*v).String()
}

func (v *prefixValue) Set(s string) error {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(s))
	if err != nil {
		return err
	}

	*v = prefixValue(prefix)
	return nil
}

func (v *prefixValue) Type() string {
	return "ipprefix"
}

func PrefixVar(f *pflag.FlagSet, p *netip.Prefix, name string, value netip.Prefix, usage string) {
	f.VarP(newPrefixValue(value, p), name, "", usage)
}

func PrefixVarP(f *pflag.FlagSet, p *netip.Prefix, name, shorthand string, value netip.Prefix, usage string) {
	f.VarP(newPrefixValue(value, p), name, shorthand, usage)
}
