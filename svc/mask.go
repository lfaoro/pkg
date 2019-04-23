// Copyright (c) 2019 Leonardo Faoro. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package svc

import (
	"strings"
	"unicode"
)

// length of string
// extract positions
// replace at positions

// Mask replaces every other 4 runes of a string with an 4 '****' runes.
// Ideal to mask sensitive data, like credit cards or social security numbers.
func Mask(data string) string {
	count := -1
	state := true
	transform := func(r rune) rune {
		if unicode.IsPunct(r) {
			return r
		}
		if count < 3 {
			count++
		} else {
			state = !state
			count = 0
		}
		if state {
			return '*'
		}
		return r
	}
	return strings.Map(transform, data)
}
