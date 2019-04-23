// Copyright (c) 2019 Leonardo Faoro. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package aesgcm implement AES encryption with GCM authentication according
// to the paper at ref: https://eprint.iacr.org/2015/102.pdf
package aesgcm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"

	"github.com/vlct-io/pkg/encrypto"

	"github.com/pkg/errors"
)

// aesgcm mplements the Encrypt/Decrypt methods
// using AES-GCM: https://eprint.iacr.org/2015/102.pdf
type aesgcm struct {
	// either 16, 24, or 32 bytes to select AES-128, AES-192, or AES-256.
	Key string
}

// validate interface conformity.
var _ encrypto.Cryptor = aesgcm{}

// New makes a new aes-gcm Cryptor.
func New(key string) encrypto.Cryptor {
	return aesgcm{
		Key: key,
	}
}

// Encrypt ciphers the plainText using the provided 16, 24 or 32 bytes key
// with AES/GCM and returns a base64 encoded string.
func (ag aesgcm) Encrypt(plainText []byte) (cypherText string, err error) {
	_key := []byte(ag.Key)
	_cipher, err := aes.NewCipher(_key)
	if err != nil {
		return "", errors.Wrap(err, "unable to create a new cipher")
	}
	gcm, err := cipher.NewGCM(_cipher)
	if err != nil {
		return "", errors.Wrap(err, "unable to wrap cipher in GCM")
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", errors.Wrap(err, "unable to read random nonce")
	}
	b := gcm.Seal(nonce, nonce, []byte(plainText), nil)
	return base64.StdEncoding.EncodeToString(b), nil
}

// Decrypt deciphers the provided base64 encoded and AES/GCM ciphered
// data returning the original plainText string.
func (ag aesgcm) Decrypt(cipherText []byte) (plainText []byte, err error) {
	_key := []byte(ag.Key)
	_cipher, err := aes.NewCipher(_key)
	if err != nil {
		return nil, errors.Wrap(err, "unable to create new cipher")
	}
	gcm, err := cipher.NewGCM(_cipher)
	if err != nil {
		return nil, errors.Wrap(err, "unable to wrap cipher in GCM")
	}
	nonceSize := gcm.NonceSize()
	if len(cipherText) < nonceSize {
		return nil, errors.Wrap(err, "unable to read random nonce")
	}
	nonce, cipherplainText := cipherText[:nonceSize], cipherText[nonceSize:]
	return gcm.Open(nil, nonce, cipherplainText, nil)
}
