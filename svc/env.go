// Copyright (c) 2019 Leonardo Faoro. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package svc

import (
	"log"
	"os"
)

// MustGetEnv retrieves the provided environment variable
// value, and panics if not found.
func MustGetEnv(variable string) string {
	v := os.Getenv(variable)
	if v == "" {
		log.Fatalf("%v environment variable not set.", variable)
	}
	return v
}

// MustGetEnvs retrieves the provided environment variables
// values, and panics if any is not found.
func MustGetEnvs(variables ...string) []string {
	var values []string
	for _, v := range variables {
		values = append(values, MustGetEnv(v))
	}
	return values
}
