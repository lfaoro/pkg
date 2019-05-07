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
	key16, err := encrypto.RandomString(16)
	assert.Nil(t, err)
	key24, err := encrypto.RandomString(24)
	assert.Nil(t, err)
	key32, err := encrypto.RandomString(32)
	assert.Nil(t, err)
	keyInvalid, _ := encrypto.RandomString(20)
	keys := []string{keyInvalid, key16, key24, key32}

	for n, key := range keys {
		t.Log("testing key: ", n)
		aes, err := aesgcm.New(key)
		if n == 0 { // invalid case
			assert.NotNil(t, err)
			continue
		} else {
			assert.Nil(t, err)
		}
		// encrypt
		ct, err := aes.Encrypt(plainText)
		assert.Nil(t, err)
		// decrypt
		pt, err := aes.Decrypt([]byte(ct))
		assert.Nil(t, err, "key %d bytes", len(key))
		assert.Equal(t, plainText, pt)
	}
}
