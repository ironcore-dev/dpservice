// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package flag

import (
	"fmt"
	"io"
	"net/netip"
	"strings"

	"github.com/spf13/pflag"
)

// -- addrSlice Value
type addrSliceValue struct {
	value   *[]netip.Addr
	changed bool
}

func newAddrSliceValue(val []netip.Addr, p *[]netip.Addr) *addrSliceValue {
	ipsv := new(addrSliceValue)
	ipsv.value = p
	*ipsv.value = val
	return ipsv
}

// Set converts, and assigns, the comma-separated IP argument string representation as the []netip.Addr value of this flag.
// If Set is called on a flag that already has a []netip.Addr assigned, the newly converted values will be appended.
func (s *addrSliceValue) Set(val string) error {
	// remove all quote characters
	rmQuote := strings.NewReplacer(`"`, "", `'`, "", "`", "")

	// read flag arguments with CSV parser
	ipStrSlice, err := readAsCSV(rmQuote.Replace(val))
	if err != nil && err != io.EOF {
		return err
	}

	// parse ip values into slice
	out := make([]netip.Addr, 0, len(ipStrSlice))
	for _, ipStr := range ipStrSlice {
		ip, err := netip.ParseAddr(strings.TrimSpace(ipStr))
		if err != nil {
			return fmt.Errorf("invalid string %q being converted to IP address: %w", ipStr, err)
		}
		out = append(out, ip)
	}

	if !s.changed {
		*s.value = out
	} else {
		*s.value = append(*s.value, out...)
	}

	s.changed = true

	return nil
}

// Type returns a string that uniquely represents this flag's type.
func (s *addrSliceValue) Type() string {
	return "addrSlice"
}

// String defines a "native" format for this netip.Addr slice flag value.
func (s *addrSliceValue) String() string {
	ipStrSlice := make([]string, len(*s.value))
	for i, ip := range *s.value {
		ipStrSlice[i] = ip.String()
	}

	out, _ := writeAsCSV(ipStrSlice)

	return "[" + out + "]"
}

func (s *addrSliceValue) fromString(val string) (netip.Addr, error) {
	return netip.ParseAddr(strings.TrimSpace(val))
}

func (s *addrSliceValue) toString(val netip.Addr) string {
	return val.String()
}

func (s *addrSliceValue) Append(val string) error {
	i, err := s.fromString(val)
	if err != nil {
		return err
	}
	*s.value = append(*s.value, i)
	return nil
}

func (s *addrSliceValue) Replace(val []string) error {
	out := make([]netip.Addr, len(val))
	for i, d := range val {
		var err error
		out[i], err = s.fromString(d)
		if err != nil {
			return err
		}
	}
	*s.value = out
	return nil
}

func (s *addrSliceValue) GetSlice() []string {
	out := make([]string, len(*s.value))
	for i, d := range *s.value {
		out[i] = s.toString(d)
	}
	return out
}

// AddrSliceVar defines a addrSlice flag with specified name, default value, and usage string.
// The argument p points to a []netip.Addr variable in which to store the value of the flag.
func AddrSliceVar(f *pflag.FlagSet, p *[]netip.Addr, name string, value []netip.Addr, usage string) {
	f.VarP(newAddrSliceValue(value, p), name, "", usage)
}

// AddrSliceVarP is like AddrSliceVar, but accepts a shorthand letter that can be used after a single dash.
func AddrSliceVarP(f *pflag.FlagSet, p *[]netip.Addr, name, shorthand string, value []netip.Addr, usage string) {
	f.VarP(newAddrSliceValue(value, p), name, shorthand, usage)
}

// AddrSlice defines a []netip.Addr flag with specified name, default value, and usage string.
// The return value is the address of a []netip.Addr variable that stores the value of that flag.
func AddrSlice(f *pflag.FlagSet, name string, value []netip.Addr, usage string) *[]netip.Addr {
	var p []netip.Addr
	AddrSliceVarP(f, &p, name, "", value, usage)
	return &p
}

// AddrSliceP is like AddrSlice, but accepts a shorthand letter that can be used after a single dash.
func AddrSliceP(f *pflag.FlagSet, name, shorthand string, value []netip.Addr, usage string) *[]netip.Addr {
	var p []netip.Addr
	AddrSliceVarP(f, &p, name, shorthand, value, usage)
	return &p
}
