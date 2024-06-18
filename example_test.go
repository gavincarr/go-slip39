package slip39_test

import (
	"encoding/hex"
	"fmt"

	"github.com/gavincarr/go-slip39"
)

func Example() {
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

	// Combine 3 of the 5 shares to recover the master secret
	shares := []string{groups[0][0], groups[0][2], groups[0][4]}
	recoveredSecret, _ := slip39.CombineMnemonicsWithPassphrase(
		shares,
		[]byte(passphrase),
	)
	fmt.Println(hex.EncodeToString(recoveredSecret))

	// Output: 5
	// bb54aac4b89dc868ba37d9cc21b2cece
}
