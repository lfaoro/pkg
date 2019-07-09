// Copyright (c) 2019 Leonardo Faoro. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package aesgcm_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/lfaoro/pkg/encrypto"
	"github.com/lfaoro/pkg/encrypto/aesgcm"
)

var plainText = []byte("hello world")

func TestAesgcm(t *testing.T) {
	key := encrypto.NewEncryptionKey()

	aes, err := aesgcm.New(key)
	assert.Nil(t, err)

	ciphertext, err := aes.Encrypt(plainText)
	assert.Nil(t, err)

	pt, err := aes.Decrypt(ciphertext)
	assert.Nil(t, err, "key %d bytes", len(key))
	assert.Equal(t, plainText, pt)
}
