// Copyright (c) 2019 Leonardo Faoro. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package cloudKMS makes it easy to interact with GCP's CloudKMS service.
package cloudKMS

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"

	"github.com/pkg/errors"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/cloudkms/v1"

	"github.com/lfaoro/pkg/encrypto"
	"github.com/lfaoro/pkg/logger"
)

// Assumes you have the "GOOGLE_APPLICATION_CREDENTIALS" environment
// variable setup in your environment with access to the Cloud KMS service.
//
// Authentication documentation: https://cloud.google.com/docs/authentication/getting-started
// Go client library: https://cloud.google.com/kms/docs/reference/libraries#client-libraries-install-go
//
// Remember to create a KeyRing and CryptoKey.
// Documentation: https://cloud.google.com/kms/docs/creating-keys
//
// Cloud KMS pricing: https://cloud.google.com/kms/pricing
//
type cloudKMS struct {
	ProjectID    string
	LocationID   string
	KeyRingID    string
	CryptoKeyID  string
	SigningKeyID string
	authedClient *http.Client
	service      *cloudkms.Service
}

// validate interface conformity.
var _ encrypto.Cryptor = cloudKMS{}
var log = logger.New("[crypter] ", nil)

// New makes a crypto.Cryptor.
func New(projectID, locationID, keyRingID, cryptoKeyID string) encrypto.Cryptor {
	ctx := context.Background()
	authedClient, err := google.DefaultClient(ctx, cloudkms.CloudPlatformScope)
	if err != nil {
		log.Fatal(err)
	}
	kmsService, err := cloudkms.New(authedClient)
	if err != nil {
		log.Fatal(err)
	}
	kms := cloudKMS{
		ProjectID:    projectID,
		LocationID:   locationID,
		KeyRingID:    keyRingID,
		CryptoKeyID:  cryptoKeyID,
		SigningKeyID: cryptoKeyID + "_sign",
		authedClient: authedClient,
		service:      kmsService,
	}
	return kms
}

// Encrypt attempts to successfully encrypt the plainText.
func (kms cloudKMS) Encrypt(plainText []byte) (string, error) {
	parentName := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s",
		kms.ProjectID, kms.LocationID, kms.KeyRingID, kms.CryptoKeyID)

	req := &cloudkms.EncryptRequest{
		Plaintext: base64.StdEncoding.EncodeToString(plainText),
	}
	res, err := kms.service.Projects.Locations.KeyRings.CryptoKeys.Encrypt(parentName, req).Do()
	if err != nil {
		return "", err
	}
	return res.Ciphertext, nil
}

// Decrypt attempts to successfully decrypt the cipherText.
func (kms cloudKMS) Decrypt(cipherText []byte) ([]byte, error) {
	parentName := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s",
		kms.ProjectID, kms.LocationID, kms.KeyRingID, kms.CryptoKeyID)

	req := &cloudkms.DecryptRequest{
		Ciphertext: base64.StdEncoding.EncodeToString(cipherText),
	}
	res, err := kms.service.Projects.Locations.KeyRings.CryptoKeys.Decrypt(parentName, req).Do()
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(res.Plaintext)
}

// Sign will sign a plaintext message using an asymmetric private key.
// example keyName: "projects/PROJECT_ID/locations/global/keyRings/RING_ID/cryptoKeys/KEY_ID/cryptoKeyVersions/1"
//
// DON't USE: not production ready
func (kms cloudKMS) Sign(message []byte) ([]byte, error) {
	var err error
	kmsService, err := cloudkms.New(kms.authedClient)
	if err != nil {
		return nil, err
	}
	// Find the digest of the message.
	digest := sha256.New()
	digest.Write(message)
	parentName := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s",
		kms.ProjectID, kms.LocationID, kms.KeyRingID, kms.CryptoKeyID)
	// Build the signing request.
	req := &cloudkms.AsymmetricSignRequest{
		Digest: &cloudkms.Digest{
			Sha256: string(digest.Sum(nil)),
		},
	}
	// Call the API.
	res, err := kmsService.Projects.Locations.KeyRings.CryptoKeys.CryptoKeyVersions.AsymmetricSign(parentName, req).Do()
	if err != nil {
		return nil, fmt.Errorf("asymmetric sign request failed: %+v", err)
	}
	return base64.StdEncoding.DecodeString(res.Signature)
}

// verifySignatureEC will verify that an 'EC_SIGN_P256_SHA256' signature is valid for a given message.
// example keyName: "projects/PROJECT_ID/locations/global/keyRings/RING_ID/cryptoKeys/KEY_ID/cryptoKeyVersions/1"
//
// DON't USE: not production ready
func (kms cloudKMS) Verify(signature, message []byte) error {
	var err error
	kmsService, err := cloudkms.New(kms.authedClient)
	if err != nil {
		return err
	}
	parentName := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s",
		kms.ProjectID, kms.LocationID, kms.KeyRingID, kms.CryptoKeyID)
	// Retrieve the public key from KMS.
	res, err := kmsService.Projects.Locations.KeyRings.CryptoKeys.CryptoKeyVersions.GetPublicKey(parentName).Do()
	if err != nil {
		return fmt.Errorf("failed to fetch public key: %+v", err)
	}
	// Parse the key.
	block, _ := pem.Decode([]byte(res.Pem))
	abstractKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %+v", err)
	}
	ecKey, ok := abstractKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("key '%s' is not EC", abstractKey)
	}
	// Verify Elliptic Curve signature.
	var parsedSig struct{ R, S *big.Int }
	_, err = asn1.Unmarshal(signature, &parsedSig)
	if err != nil {
		return fmt.Errorf("failed to parse signature bytes: %+v", err)
	}
	hash := sha256.New()
	hash.Write(message)
	digest := hash.Sum(nil)
	if !ecdsa.Verify(ecKey, digest, parsedSig.R, parsedSig.S) {
		return errors.New("signature verification failed")
	}
	return nil
}
