// Copyright (c) 2019 Leonardo Faoro. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package security

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewToken(t *testing.T) {
	assert.Panics(t, func() {
		NewToken(4, false)
	})

	tlen := 32
	tok := NewToken(tlen, false)
	assert.Equal(t, len(tok), tlen, "token length")
	assert.Contains(t, tok, "tok_", nil)
	t.Log("token:", tok)

	ttok := NewToken(tlen, true)
	assert.Contains(t, ttok, "test_tok_", nil)
}
