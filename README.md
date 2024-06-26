go-slip39
=========

[![PkgGoDev](https://pkg.go.dev/badge/gavincarr/go-slip39)](https://pkg.go.dev/github.com/gavincarr/go-slip39)
[![MIT License](https://img.shields.io/github/license/gavincarr/go-slip39.svg?maxAge=2592000&color=blue)](https://github.com/gavincarr/go-slip39/blob/master/LICENCE)

[![Go Build Status](https://github.com/gavincarr/go-slip39/actions/workflows/go.yml/badge.svg)](https://github.com/gavincarr/go-slip39/actions/workflows/go.yml/badge.svg)
[![Go Report Card](https://goreportcard.com/badge/github.com/gavincarr/go-slip39)](https://goreportcard.com/report/github.com/gavincarr/go-slip39)

A SLIP-0039 library for Go. Specifically, this library is a port of the
[SLIP-0039 python reference implementation](http://github.com/trezor/python-shamir-mnemonic/) to Go.

SLIP-0039 describes a standard and interoperable implementation of Shamir's
secret sharing (SSS). SSS splits a secret into unique parts which can be
distributed among participants, and requires a specified minimum number of
parts to be supplied in order to reconstruct the original secret. Knowledge of
fewer than the required number of parts does not leak information about the
secret.

Specification
-------------

See https://github.com/satoshilabs/slips/blob/master/slip-0039.md for the full
SLIP-0039 specification.

Security
--------

This implementation is not using any hardening techniques. Secrets are passed
in the open, and calculations are most likely vulnerable to side-channel attacks.
The code has not been audited by security professionals. Use at your own risk.

At the very least, you should not use this library for non-testing purposes
or with sensitive secrets outside an air-gapped live system such as
[Tails](https://tails.net/).

CLI
---

No executables are provided with this library. You can write your own tools
pretty simply, or I have a sister project called
[seedkit](https://github.com/gavincarr/seedkit/) which provides a CLI that
makes use of this library.

Usage
-----

```go
package main

import (
	"encoding/hex"
	"fmt"

	"github.com/gavincarr/go-slip39"
)

func main() {
	masterSecret := "bb54aac4b89dc868ba37d9cc21b2cece"
	passphrase := "TREZOR"

	// Generate a single group of 3 of 5 shares for masterSecret
	masterSecretBytes, _ := hex.DecodeString(masterSecret)
	groupCount := 1
	memberGroupParams := []slip39.MemberGroupParameters{{3, 5}}
	groups, _ := slip39.GenerateMnemonicsWithPassphrase(
		groupCount,
		memberGroupParams,
		masterSecretBytes,
		[]byte(passphrase),
	)
	fmt.Println(len(groups[0]))
	// Output: 5

	// Combine 3 of the 5 shares to recover the master secret
	shares := []string{groups[0][0], groups[0][2], groups[0][4]}
	recoveredSecret, _ := slip39.CombineMnemonicsWithPassphrase(
		shares,
		[]byte(passphrase),
	)
	fmt.Println(hex.EncodeToString(recoveredSecret))
	// Output: bb54aac4b89dc868ba37d9cc21b2cece
}
```

