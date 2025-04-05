# SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
# SPDX-License-Identifier: Apache-2.0

from helpers import *

def test_dhcpv4_vf0(prepare_ifaces):
	request_ip(VM1, check_hostname=True)

def test_dhcpv4_vf1(prepare_ifaces):
	request_ip(VM2)
