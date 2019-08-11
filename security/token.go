// Copyright (c) 2019 Leonardo Faoro. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package security

import (
	"strings"

	"github.com/gobuffalo/uuid"
)

// NewToken returns a random string prefixed with `tok_` or
// `tok_test_` if isTest == true.
//
// The minimum token length is 5, it panics otherwise.
//
// Example:
// NewToken(32, false) => "tok_944edcfbb3f44f75920c365c0095"
func NewToken(len int, isTest bool) string {
	if len < 5 {
		panic("minimum token length is 5")
	}
	// ensure the generator is seeded
	RandomBytes(32)
	prefix := "tok_"
	if isTest {
		prefix += "tok_test_"
	}
	uid := uuid.Must(uuid.NewV4()).String()
	uid = strings.Replace(uid, "-", "", -1)
	pwd := prefix + uid
	return pwd[:len]
}
