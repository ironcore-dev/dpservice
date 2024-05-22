// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package flag

import (
	"net/netip"
	"strings"

	"github.com/spf13/pflag"
)

type addrValue netip.Addr

func newAddrValue(val netip.Addr, p *netip.Addr) *addrValue {
	*p = val
	return (*addrValue)(p)
}

func (v *addrValue) String() string {
	return netip.Addr(*v).String()
}

func (v *addrValue) Set(s string) error {
	addr, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return err
	}

	*v = addrValue(addr)
	return nil
}

func (v *addrValue) Type() string {
	return "ip"
}

func AddrVar(f *pflag.FlagSet, p *netip.Addr, name string, value netip.Addr, usage string) {
	f.VarP(newAddrValue(value, p), name, "", usage)
}

func AddrVarP(f *pflag.FlagSet, p *netip.Addr, name, shorthand string, value netip.Addr, usage string) {
	f.VarP(newAddrValue(value, p), name, shorthand, usage)
}
