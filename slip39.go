// Package slip39 is a Go implementation of the SLIP-0039 spec, implementing
// Shamir's Secret Sharing Scheme.
//
// The official SLIP-0039 spec can be found at
// https://github.com/satoshilabs/slips/blob/master/slip-0039.md
package slip39

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

const (
	minMnemonicLengthWords = 20

	radixBits                   = 10
	idLengthBits                = 15
	extendableFlagLengthBits    = 1
	iterationExponentLengthBits = 4
	idExpLengthWords            = 2
	checksumLengthWords         = 3
	metadataLengthWords         = idExpLengthWords + 2 + checksumLengthWords

	customizationStringNonExtendable = "shamir"
	customizationStringExtendable    = "shamir_extendable"

	shift5Bits  = 1 << 5
	shift10Bits = 1 << 10
	last10Bits  = 1<<10 - 1
	shift30Bits = 1 << 30
	last30Bits  = 1<<30 - 1
)

var (
	bigOne          = big.NewInt(1)
	shift5BitsMask  = big.NewInt(shift5Bits)
	shift10BitsMask = big.NewInt(shift10Bits)
	shift30BitsMask = big.NewInt(shift30Bits)
	last30BitsMask  = big.NewInt(last30Bits)

	ErrInvalidMnemonic = errors.New("Invalid mnemonic")
	ErrInvalidChecksum = errors.New("Invalid checksum")

	// ErrMasterSecretLengthInvalid is returned when trying to use a master
	// secret with an invalid size
	ErrMasterSecretLengthInvalid = errors.New("Master secret length must be >= 128 and be a multiple of 16")
)

type Share struct {
	Identifier      int
	Extendable      int
	Exponent        int
	GroupIndex      int
	GroupThreshold  int
	GroupCount      int
	MemberIndex     int
	MemberThreshold int
	ShareValues     []byte
}

func SplitSecret(threshold, numShares int, secret []byte) ([]int, error) {
	if len(secret) < 128/8 || len(secret)%2 != 0 {
		return nil, ErrMasterSecretLengthInvalid
	}

	return []int{}, nil
}

func ParseShare(mnemonic string) (Share, error) {
	var share Share

	mnemonicSlice, isValid := splitMnemonicWords(strings.ToLower(mnemonic))
	if !isValid {
		return share, ErrInvalidMnemonic
	}

	paddingLen := (radixBits * (len(mnemonicSlice) - metadataLengthWords)) % 16
	//fmt.Printf("paddingLen: %d\n", paddingLen)
	if paddingLen > 8 {
		return share, ErrInvalidMnemonic
	}

	var data = make([]int, len(mnemonicSlice))
	for i, v := range mnemonicSlice {
		index, found := wordmap[v]
		if !found {
			return share,
				fmt.Errorf("Invalid mnemonic: word `%v` not found in wordmap", v)
		}
		data[i] = index
	}
	//fmt.Printf("data: %v\n", data)

	idExpData := data[:idExpLengthWords]
	idExpInt := intFromWordIndices(idExpData)
	//fmt.Printf("idExpInt: %d\n", idExpInt)

	share.Identifier = idExpInt >>
		(extendableFlagLengthBits + iterationExponentLengthBits)
	share.Extendable = idExpInt >> iterationExponentLengthBits & 1
	share.Exponent = idExpInt & ((1 << iterationExponentLengthBits) - 1)

	// Verify checksum
	cs := customizationStringNonExtendable
	if share.Extendable != 0 {
		cs = customizationStringExtendable
	}
	/*
		fmt.Printf("createChecksum: %v\n",
			rs1024CreateChecksum(customizationStringNonExtendable,
				data[:len(data)-checksumLengthWords]))
	*/
	if !rs1024VerifyChecksum(cs, data) {
		//fmt.Printf("invalid checksum!\n")
		return share, ErrInvalidChecksum
	}

	shareParamsData := data[idExpLengthWords : idExpLengthWords+2]
	shareParamsInt := intFromWordIndices(shareParamsData)
	shareParams := intToIndices(shareParamsInt, 5, 4)
	share.GroupIndex = shareParams[0]
	share.GroupThreshold = shareParams[1] + 1
	share.GroupCount = shareParams[2] + 1
	share.MemberIndex = shareParams[3]
	share.MemberThreshold = shareParams[4] + 1

	if share.GroupCount < share.GroupThreshold {
		return share,
			fmt.Errorf(`Invalid mnemonic "%s ...". Group threshold cannot be greater than group count`,
				strings.Join(mnemonicSlice[:idExpLengthWords+2], " "))
	}

	valueData := data[idExpLengthWords+2 : len(data)-checksumLengthWords]
	valueByteCount := bitsToBytes(radixBits*len(valueData) - paddingLen)
	valueInt := bigintFromWordIndices(valueData)
	//fmt.Printf("valueInt: %d\n", valueInt)
	share.ShareValues = valueInt.Bytes()
	if len(share.ShareValues) > valueByteCount {
		return share,
			fmt.Errorf(`Invalid mnemonic padding for "%s ..."`,
				strings.Join(mnemonicSlice[:idExpLengthWords+2], " "))
	}

	return share, nil
}

func splitMnemonicWords(mnemonic string) ([]string, bool) {
	words := strings.Fields(mnemonic)

	if len(words) < minMnemonicLengthWords {
		return nil, false
	}

	return words, true
}

func intFromWordIndices(indices []int) int {
	if len(indices) > 4 {
		panic("intFromWordIndices: indices length must be <= 4")
	}
	value := 0
	for _, index := range indices {
		value = (value << 10) + index
	}
	return value
}

func bigintFromWordIndices(indices []int) *big.Int {
	var wordBytes [2]byte
	var b = big.NewInt(0)
	for _, index := range indices {
		binary.BigEndian.PutUint16(wordBytes[:], uint16(index))
		b.Mul(b, shift10BitsMask)
		b.Or(b, big.NewInt(0).SetBytes(wordBytes[:]))
	}
	return b
}

func intToIndices(value, length, bits int) []int {
	mask := (1 << bits) - 1
	indices := make([]int, 0, length)
	for i := length - 1; i >= 0; i-- {
		indices = append(indices, (value>>(i*bits))&mask)
	}
	return indices
}

func bitsToBytes(n int) int {
	return (n + 8 - 1) / 8
}

func stringToInts(s string) []int {
	ints := make([]int, len(s))
	for i := 0; i < len(s); i++ {
		ints[i] = int(s[i])
	}
	return ints
}

func rs1024Polymod(values []int) int {
	gen := []int{
		0xe0e040, 0x1c1c080, 0x3838100, 0x7070200, 0xe0e0009,
		0x1c0c2412, 0x38086c24, 0x3090fc48, 0x21b1f890, 0x3f3f120,
	}
	chk := 1

	for _, v := range values {
		b := chk >> 20
		chk = ((chk & 0xfffff) << 10) ^ v
		for i := range 10 {
			if (b>>i)&1 != 0 {
				chk ^= gen[i]
			} else {
				chk ^= 0
			}
		}
	}

	return chk
}

func rs1024VerifyChecksum(cs string, data []int) bool {
	values := append(stringToInts(cs), data...)
	return rs1024Polymod(values) == 1
}

func rs1024CreateChecksum(cs string, data []int) []int {
	values := append(stringToInts(cs), data...)
	values = append(values, []int{0, 0, 0}...)
	polymod := rs1024Polymod(values) ^ 1
	checksum := make([]int, checksumLengthWords)
	for i := range checksumLengthWords {
		checksum[i] = (polymod >> 10 * (2 - i)) & 1023
	}
	return checksum
}
