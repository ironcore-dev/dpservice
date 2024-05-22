// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package errors

import (
	"errors"
	"fmt"

	dpdkproto "github.com/ironcore-dev/dpservice-go/proto"
)

const (
	// Error codes
	// Returned for unknown request type
	BAD_REQUEST = 101
	// General-purpose errors
	NOT_FOUND      = 201
	ALREADY_EXISTS = 202
	WRONG_TYPE     = 203
	BAD_IPVER      = 204
	NO_VM          = 205
	NO_VNI         = 206
	ITERATOR       = 207
	OUT_OF_MEMORY  = 208
	LIMIT_REACHED  = 209
	ALREADY_ACTIVE = 210
	NOT_ACTIVE     = 211
	ROLLBACK       = 212
	RTE_RULE_ADD   = 213
	RTE_RULE_DEL   = 214
	// Specific errors
	ROUTE_EXISTS    = 301
	ROUTE_NOT_FOUND = 302
	ROUTE_INSERT    = 303
	ROUTE_BAD_PORT  = 304
	ROUTE_RESET     = 305
	DNAT_NO_DATA    = 321
	DNAT_CREATE     = 322
	DNAT_EXISTS     = 323
	SNAT_NO_DATA    = 341
	SNAT_CREATE     = 342
	SNAT_EXISTS     = 343
	VNI_INIT4       = 361
	VNI_INIT6       = 362
	VNI_FREE4       = 363
	VNI_FREE6       = 364
	PORT_START      = 381
	PORT_STOP       = 382
	VNF_INSERT      = 401
	VM_HANDLE       = 402
	NO_BACKIP       = 421
	NO_LB           = 422
	NO_DROP_SUPPORT = 441

	// os.Exit value
	CLIENT_ERROR = 1
	SERVER_ERROR = 2

	StatusErrorString = "rpc error"
)

type StatusError struct {
	errorCode uint32
	message   string
}

func (s *StatusError) Message() string {
	return s.message
}

func (s *StatusError) ErrorCode() uint32 {
	return s.errorCode
}

func (s *StatusError) Error() string {
	if s.message != "" {
		return fmt.Sprintf("[error code %d] %s", s.errorCode, s.message)
	}
	return fmt.Sprintf("error code %d", s.errorCode)
}

func NewStatusError(errorCode uint32, message string) *StatusError {
	return &StatusError{
		errorCode: errorCode,
		message:   message,
	}
}

// Ignore requested status errors
func GetError(status *dpdkproto.Status, ignoredErrors [][]uint32) error {
	if status.Code == 0 {
		return nil
	}
	if len(ignoredErrors) > 0 {
		for _, ignoredError := range ignoredErrors[0] {
			if status.Code == ignoredError {
				return nil
			}
		}
	}
	return NewStatusError(status.Code, status.Message)
}

func IsStatusErrorCode(err error, errorCodes ...uint32) bool {
	statusError := &StatusError{}
	if !errors.As(err, &statusError) {
		return false
	}

	for _, errorCode := range errorCodes {
		if statusError.ErrorCode() == errorCode {
			return true
		}
	}
	return false
}

func IgnoreStatusErrorCode(err error, errorCodes ...uint32) error {
	if IsStatusErrorCode(err, errorCodes...) {
		return nil
	}
	return err
}

// Create array of status error codes to be ignored
func Ignore(errorCodes ...uint32) []uint32 {
	arr := make([]uint32, 0, len(errorCodes))
	arr = append(arr, errorCodes...)

	return arr
}
