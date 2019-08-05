// Copyright (c) 2019 Leonardo Faoro. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package security

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHash(t *testing.T) {
	data := "hello world"
	sum := Hash([]byte(data))
	assert.NotEqual(t, "", sum)
	assert.Equal(t, "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9", sum)
}

func BenchmarkHash32(b *testing.B) {
	data, _ := RandomString(32)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Hash([]byte(data))
	}
}

func BenchmarkHash64(b *testing.B) {
	data, _ := RandomString(64)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Hash([]byte(data))
	}
}
