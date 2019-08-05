// Copyright (c) 2019 Leonardo Faoro. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package security

import (
	"net/http"
	"time"

	"github.com/gorilla/mux"
)

// DefaultServer returns a http.Server with TLS security defaults
// and sane timeouts.
func DefaultServer(hostPort string, router *mux.Router) *http.Server {
	return &http.Server{
		Addr:              hostPort,
		Handler:           router,
		TLSConfig:         DefaultTLSConfig(),
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       120 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
	}
}
