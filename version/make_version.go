// Copyright (c) 2019 Leonardo Faoro. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build ignore

// The make_version program is run by go generate to compile a version stamp
// to be compiled into the binary.
// It does nothing unless $COMMIT_SHA is set, which is true only during
// the release process.
package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"time"
)

func main() {
	log.SetPrefix("make_version")
	log.SetFlags(0)

	version := os.Getenv("COMMIT_SHA")
	if version == "" {
		return
	}

	output := fmt.Sprintf(outputFormat, time.Now().In(time.UTC).Format(time.UnixDate), version)

	err := ioutil.WriteFile("git_version.go", []byte(output), 0664)
	if err != nil {
		log.Fatal(err)
	}
}

const outputFormat = `
// Code generated by 'go run makeversion.go'. DO NOT EDIT.

package version

import (
	"fmt"
	"time"
)

func init() {
	var err error
	BuildTime, err = time.Parse(time.UnixDate, %[1]q)
	if err != nil {
		panic(err)
	}
	GitSHA = fmt.Sprintf("%%s", %[2]q)
}
`
