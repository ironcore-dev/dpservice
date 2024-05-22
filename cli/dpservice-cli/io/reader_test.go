// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package io_test

import (
	"bytes"

	. "github.com/ironcore-dev/dpservice-cli/io"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Reader", func() {
	Context("CheckpointReader", func() {
		var (
			data []byte
			rd   *CheckpointReader
		)
		BeforeEach(func() {
			data = []byte("foo.bar.baz.qux")
			rd = NewCheckpointReader(bytes.NewReader(data))
		})

		It("should allow unreading", func() {
			fooBytes := make([]byte, 3)
			n, err := rd.Read(fooBytes)
			Expect(n).To(Equal(3))
			Expect(err).NotTo(HaveOccurred())

			Expect(fooBytes).To(Equal([]byte("foo")))

			n, err = rd.Unread()
			Expect(err).NotTo(HaveOccurred())
			Expect(n).To(Equal(3))

			fooBytes = make([]byte, 3)
			n, err = rd.Read(fooBytes)
			Expect(n).To(Equal(3))
			Expect(err).NotTo(HaveOccurred())
			Expect(fooBytes).To(Equal([]byte("foo")))
		})

		It("should allow unreading uneven amounts", func() {
			fooDotBarBytes := make([]byte, 7)
			n, err := rd.Read(fooDotBarBytes)
			Expect(n).To(Equal(7))
			Expect(err).NotTo(HaveOccurred())

			Expect(fooDotBarBytes).To(Equal([]byte("foo.bar")))

			n, err = rd.Unread()
			Expect(err).NotTo(HaveOccurred())
			Expect(n).To(Equal(7))

			fooBytes := make([]byte, 3)
			n, err = rd.Read(fooBytes)
			Expect(n).To(Equal(3))
			Expect(err).NotTo(HaveOccurred())

			dotBarBytes := make([]byte, 4)
			n, err = rd.Read(dotBarBytes)
			Expect(n).To(Equal(4))
			Expect(err).NotTo(HaveOccurred())
			Expect(dotBarBytes).To(Equal([]byte(".bar")))
		})
	})
})
