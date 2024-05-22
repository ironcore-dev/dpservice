// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package io

import (
	"bytes"
	"io"
)

type CheckpointReader struct {
	offset int
	src    io.Reader
	buf    bytes.Buffer
}

func NewCheckpointReader(src io.Reader) *CheckpointReader {
	return &CheckpointReader{
		src: src,
	}
}

func (r *CheckpointReader) Read(p []byte) (n int, err error) {
	n, err = io.MultiReader(bytes.NewReader(r.buf.Bytes()[r.offset:]), io.TeeReader(r.src, &r.buf)).Read(p)
	r.offset += n
	return n, err
}

func (r *CheckpointReader) Checkpoint() {
	r.buf.Reset()
	r.offset = 0
}

func (r *CheckpointReader) Unread() (n int, err error) {
	n = r.offset
	r.offset = 0
	return n, nil
}
