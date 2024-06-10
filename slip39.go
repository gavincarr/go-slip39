// Package slip39 is a Go implementation of the SLIP-0039 spec, implementing
// Shamir's Secret Sharing Scheme.
//
// The official SLIP-0039 spec can be found at
// https://github.com/satoshilabs/slips/blob/master/slip-0039.md
package slip39

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/xdg-go/pbkdf2"
)

const (
	minMnemonicLengthWords        = 20
	customizationStringOriginal   = "shamir"
	customizationStringExtendable = "shamir_extendable"

	radixBits                = 10
	idLengthBits             = 15
	extendableFlagLengthBits = 1
	iterationExpLengthBits   = 4
	idExpLengthWords         = 2
	groupPrefixLengthWords   = idExpLengthWords + 1
	checksumLengthWords      = 3
	metadataLengthWords      = idExpLengthWords + 2 + checksumLengthWords

	shift5Bits  = 1 << 5
	shift10Bits = 1 << 10
	last10Bits  = 1<<10 - 1
	shift30Bits = 1 << 30
	last30Bits  = 1<<30 - 1

	// cipher constants
	baseIterationCount = 10000 // The minimum number of iterations for PBKDF2
	roundCount         = 4     // The number of rounds to use in the Feistel cipher
	secretIndex        = 255   // The index of the shared secret share
	digestIndex        = 254   // The index of the shared secret digest share
)

var (
	bigOne          = big.NewInt(1)
	shift5BitsMask  = big.NewInt(shift5Bits)
	shift10BitsMask = big.NewInt(shift10Bits)
	last10BitsMask  = big.NewInt(last10Bits)
	shift30BitsMask = big.NewInt(shift30Bits)
	last30BitsMask  = big.NewInt(last30Bits)

	// ErrInvalidChecksum is returned when the checksum on a mnemonic is invalid
	ErrInvalidChecksum = errors.New("Invalid checksum")

	// ErrInvalidMnemonic is returned when a mnemonic is invalid
	ErrInvalidMnemonic = errors.New("Invalid mnemonic")

	// ErrEmptyShareGroup is returned when a share group is empty
	ErrEmptyShareGroup = errors.New("the share group is empty")

	// ErrInvalidMnemonicSharedSecretDigest is returned when a mnemonic has an
	// invalid shared secret digest
	ErrInvalidMnemonicSharedSecretDigest = errors.New("invalid shared secret digest")

	// ErrInvalidMasterSecretLength is returned when trying to use a (decrypted)
	// master secret with an invalid length
	ErrInvalidMasterSecretLength = errors.New("master secret length must be >= 128 and be a multiple of 16")

	// ErrInvalidEncryptedMasterSecretLength is returned when an encrypted master
	// secret has an invalid length
	ErrInvalidEncryptedMasterSecretLength = errors.New("the length of the encrypted master secret must be an even number")
)

type shareCommonParameters struct {
	identifier        int
	extendable        int
	iterationExponent int
	groupThreshold    int
	groupCount        int
}

type shareGroupParameters struct {
	shareCommonParameters
	groupIndex      int
	memberThreshold int
}

type shareStruct struct {
	shareGroupParameters
	memberIndex int
	shareValues []byte
}

type shareGroup struct {
	shares []shareStruct
}

type shareGroupMap map[int]shareGroup

type rawShare struct {
	x    int
	data []byte
}

type encryptedMasterSecret struct {
	identifier        int
	extendable        bool
	iterationExponent int
	ciphertext        []byte
}

func (ems encryptedMasterSecret) decrypt(passphrase []byte) ([]byte, error) {
	return cipherDecrypt(ems.ciphertext, passphrase,
		ems.iterationExponent, ems.identifier, ems.extendable)
}

func zipBytes(a, b []byte) [][2]byte {
	length := len(a)
	if len(b) < length {
		length = len(b)
	}
	zip := make([][2]byte, length)
	for i := range length {
		x := byte(0)
		y := byte(0)
		if len(a) > i {
			x = a[i]
		}
		if len(b) > i {
			y = b[i]
		}
		zip[i] = [2]byte{x, y}
	}
	return zip
}

func xor(a, b []byte) []byte {
	c := zipBytes(a, b)
	xor := make([]byte, len(c))
	for i := range len(c) {
		xor[i] = c[i][0] ^ c[i][1]
	}
	return xor
}

func roundFunction(i int, passphrase []byte, e int, salt, r []byte) []byte {
	b := append([]byte{byte(i)}, passphrase...)
	s := append(salt, r...)
	iterations := (baseIterationCount << e) / roundCount
	return pbkdf2.Key(b, s, iterations, len(r), sha256.New)
}

func getSalt(identifier int, extendable bool) []byte {
	if extendable {
		return []byte{}
	}
	idBytes := [2]byte{}
	binary.BigEndian.PutUint16(idBytes[:], uint16(identifier))
	return append([]byte(customizationStringOriginal), idBytes[0], idBytes[1])
}

func cipherDecrypt(
	ems, passphrase []byte,
	iterationExponent, identifier int,
	extendable bool,
) ([]byte, error) {
	if len(ems)%2 != 0 {
		return nil, ErrInvalidEncryptedMasterSecretLength
	}

	l := ems[:len(ems)/2]
	r := ems[len(ems)/2:]
	salt := getSalt(identifier, extendable)
	for i := roundCount - 1; i >= 0; i-- {
		f := roundFunction(i, passphrase, iterationExponent, salt, r)
		fmt.Fprintf(os.Stderr, "cipherDecrypt3: i %d, f %q\n", i, f)
		l, r = r, xor(l, f)
	}

	return append(r, l...), nil
}

func splitMnemonicWords(mnemonic string) ([]string, bool) {
	words := strings.Fields(mnemonic)

	if len(words) < minMnemonicLengthWords {
		return nil, false
	}

	return words, true
}

// roundBits returns the number of `radixBits`-sized digits required to store a
// `n`-bit value
func roundBits(bits, radixBits int) int {
	return (bits + radixBits - 1) / radixBits
}

// padByteSlice returns a byte slice of the given size with contents of the
// given slice left padded and any empty spaces filled with zeros
func padByteSlice(slice []byte, length int) []byte {
	offset := length - len(slice)
	if offset <= 0 {
		return slice
	}

	newSlice := make([]byte, length)
	copy(newSlice[offset:], slice)

	return newSlice
}

func intToIndices(value, length, bits int) []int {
	mask := (1 << bits) - 1
	indices := make([]int, 0, length)
	for i := length - 1; i >= 0; i-- {
		indices = append(indices, (value>>(i*bits))&mask)
	}
	return indices
}

// bitesToBytes rounds up bit count to bytes
func bitsToBytes(bits int) int {
	return roundBits(bits, 8)
}

// bitsToWords rounds up bit count to a multiple of radixBits word size
func bitsToWords(bits int) int {
	return roundBits(bits, radixBits)
}

func stringToInts(s string) []int {
	ints := make([]int, len(s))
	for i := 0; i < len(s); i++ {
		ints[i] = int(s[i])
	}
	return ints
}

func intFromWordIndices(indices []int) int {
	if len(indices) > 4 {
		panic("intFromWordIndices: indices length must be <= 4")
	}
	value := 0
	for _, index := range indices {
		value = (value << radixBits) + index
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

func intToWordIndices(value int, length int) []int {
	return intToIndices(value, length, radixBits)
}

func bigintToWordIndices(b *big.Int, length int) []int {
	indices := make([]int, length)
	// Throwaway big.Int for AND masking
	word := big.NewInt(0)
	for i := length - 1; i >= 0; i-- {
		// Get 10 rightmost bits and bitshift 10 to the right
		word.And(b, last10BitsMask)
		b.Div(b, shift10BitsMask)

		// Get the bytes representing the 10 bits as a 2-byte slice
		wordBytes := padByteSlice(word.Bytes(), 2)

		// Converts wordBytes to an index and add to indices
		indices[i] = int(binary.BigEndian.Uint16(wordBytes))
	}
	return indices
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

func rs1024CreateChecksum(data []int, cs string) []int {
	values := append(stringToInts(cs), data...)
	values = append(values, []int{0, 0, 0}...)
	polymod := rs1024Polymod(values) ^ 1
	checksum := make([]int, checksumLengthWords)
	for i := range checksumLengthWords {
		checksum[i] = (polymod >> (10 * (2 - i))) & 1023
	}
	return checksum
}

func (s shareStruct) encodeIDExp() []int {
	idExpInt := s.identifier << (iterationExpLengthBits + extendableFlagLengthBits)
	idExpInt += s.extendable << iterationExpLengthBits
	idExpInt += s.iterationExponent
	return intToWordIndices(idExpInt, idExpLengthWords)
}

func (s shareStruct) encodeShareParams() []int {
	// Each value is 4 bits, for 20 bits total
	val := s.groupIndex
	val <<= 4
	val += s.groupThreshold - 1
	val <<= 4
	val += s.groupCount - 1
	val <<= 4
	val += s.groupIndex
	val <<= 4
	val += s.memberThreshold - 1
	// Group parameters are 2 words
	return intToWordIndices(val, 2)
}

func (s shareStruct) encode(valueData []int) []int {
	shareData := []int{}
	shareData = append(shareData, s.encodeIDExp()...)
	shareData = append(shareData, s.encodeShareParams()...)
	shareData = append(shareData, valueData...)
	return shareData
}

func (s shareStruct) customizationString() string {
	if s.extendable != 0 {
		return customizationStringExtendable
	}
	return customizationStringOriginal
}

// words converts share data to a share mnemonic
func (s shareStruct) words() ([]string, error) {
	valueWordCount := bitsToWords(len(s.shareValues) * 8)
	valueInt := big.NewInt(0).SetBytes(s.shareValues)
	valueData := bigintToWordIndices(valueInt, valueWordCount)

	shareData := s.encode(valueData)
	checksum := rs1024CreateChecksum(shareData, s.customizationString())
	//fmt.Fprintf(os.Stderr, "shareData: %v, customizationString: %s, checksum: %v\n",
	//shareData, s.customizationString(), checksum)
	shareData = append(shareData, checksum...)

	words := make([]string, 0, len(shareData))
	for _, wordIndex := range shareData {
		word := wordlist[wordIndex]
		if word == "" {
			return nil, fmt.Errorf("invalid share wordIndex %d", wordIndex)
		}
		words = append(words, word)
	}
	return words, nil
}

func SplitSecret(threshold, numShares int, secret []byte) ([]int, error) {
	if len(secret) < 128/8 || len(secret)%2 != 0 {
		return nil, ErrInvalidMasterSecretLength
	}

	return []int{}, nil
}

func parseShare(mnemonic string) (shareStruct, error) {
	var share shareStruct

	mnemonicData, isValid := splitMnemonicWords(strings.ToLower(mnemonic))
	if !isValid {
		return share, ErrInvalidMnemonic
	}

	paddingLen := (radixBits * (len(mnemonicData) - metadataLengthWords)) % 16
	//fmt.Printf("paddingLen: %d\n", paddingLen)
	if paddingLen > 8 {
		return share, ErrInvalidMnemonic
	}

	var data = make([]int, len(mnemonicData))
	for i, v := range mnemonicData {
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

	share.identifier = idExpInt >>
		(extendableFlagLengthBits + iterationExpLengthBits)
	share.extendable = idExpInt >> iterationExpLengthBits & 1
	share.iterationExponent = idExpInt & ((1 << iterationExpLengthBits) - 1)

	// Verify checksum
	cs := share.customizationString()
	/*
		fmt.Printf("createChecksum: %v\n",
			rs1024CreateChecksum(customizationStringOriginal,
				data[:len(data)-checksumLengthWords]))
	*/
	if !rs1024VerifyChecksum(cs, data) {
		//fmt.Printf("invalid checksum!\n")
		return share, ErrInvalidChecksum
	}

	shareParamsData := data[idExpLengthWords : idExpLengthWords+2]
	shareParamsInt := intFromWordIndices(shareParamsData)
	shareParams := intToIndices(shareParamsInt, 5, 4)
	share.groupIndex = shareParams[0]
	share.groupThreshold = shareParams[1] + 1
	share.groupCount = shareParams[2] + 1
	share.memberIndex = shareParams[3]
	share.memberThreshold = shareParams[4] + 1

	if share.groupCount < share.groupThreshold {
		return share,
			fmt.Errorf(`Invalid mnemonic "%s ...". Group threshold cannot be greater than group count`,
				strings.Join(mnemonicData[:idExpLengthWords+2], " "))
	}

	valueData := data[idExpLengthWords+2 : len(data)-checksumLengthWords]
	valueByteCount := bitsToBytes(radixBits*len(valueData) - paddingLen)
	valueInt := bigintFromWordIndices(valueData)
	//fmt.Printf("valueInt: %d\n", valueInt)
	share.shareValues = valueInt.Bytes()
	if len(share.shareValues) > valueByteCount {
		return share,
			fmt.Errorf(`Invalid mnemonic padding for "%s ..."`,
				strings.Join(mnemonicData[:idExpLengthWords+2], " "))
	}

	return share, nil
}

// newShareGroupMap creates a new shareGroupMap from a slice of mnemonics,
// or returns an error.
func newShareGroupMap(mnemonics []string) (shareGroupMap, error) {
	commonParams := mapset.NewSet[shareCommonParameters]()
	groups := make(shareGroupMap)
	for _, mnemonic := range mnemonics {
		share, err := parseShare(mnemonic)
		if err != nil {
			return nil, err
		}
		commonParams.Add(share.shareCommonParameters)
		group, ok := groups[share.groupIndex]
		if !ok {
			groups[share.groupIndex] = shareGroup{shares: []shareStruct{share}}
		} else {
			group.shares = append(group.shares, share)
			groups[share.groupIndex] = group
		}
	}
	if commonParams.Cardinality() != 1 {
		return nil,
			fmt.Errorf("All mnemonics must begin with the same %d words, must have the same group threshold and the same group count.", idExpLengthWords)
	}
	return groups, nil
}

func groupRawShares(group shareGroup) []rawShare {
	grs := make([]rawShare, len(group.shares))
	for i, s := range group.shares {
		grs[i] = rawShare{
			x:    s.groupIndex,
			data: s.shareValues,
		}
	}
	return grs
}

func recoverSecret(threshold int, shares []rawShare) ([]byte, error) {
	// If the threshold is 1, then the digest of the shared secret is not used
	if threshold == 1 {
		return shares[0].data, nil
	}

	var sharedSecret []byte

	return nil, errors.New("recoverSecret: multi-share support not implemented yet")
	/*
		TODO
		sharedSecret := interpolate(shares, secretIndex)
		digestShare := interpolate(shares, digestIndex)
		digest := digestShare[:digestLengthBytes]
		randomPart := digestShare[digestLengthBytes:]

		if digest != createDigest(randomPart, sharedSecret) {
			return nil, ErrInvalidMnemonicSharedSecretDigest
		}
	*/

	return sharedSecret, nil
}

// recoverEMS combines the shares in shareGroupMap, recovers the group metadata,
// and returns the encrypted master secret. If there are any problems with the
// share group it returns an error.
func recoverEMS(groups shareGroupMap) (encryptedMasterSecret, error) {
	ems := encryptedMasterSecret{}

	if len(groups) == 0 {
		return ems, ErrEmptyShareGroup
	}

	var params shareCommonParameters
	i := 0
	for _, group := range groups {
		if i == 0 {
			params = group.shares[0].shareCommonParameters
			if len(groups) < params.groupThreshold {
				return ems, fmt.Errorf("insufficient share groups (%d supplied, %d required)",
					len(groups), params.groupThreshold)
			}

			if len(groups) != params.groupThreshold {
				return ems, fmt.Errorf("wrong number of share groups (%d supplied, %d required)",
					len(groups), params.groupThreshold)
			}
		}

		//fmt.Fprintf(os.Stderr, "recoverEMS: group.shares %d, shares[0].memberThreshold %d\n", len(group.shares), group.shares[0].memberThreshold)
		if len(group.shares) != group.shares[0].memberThreshold {
			shareWords, err := group.shares[0].words()
			if err != nil {
				return ems, fmt.Errorf("wrong number of shares (%d supplied, %d required for group starting with %q)",
					len(group.shares), group.shares[0].memberThreshold,
					"unknown")
			}
			prefix := strings.Join(shareWords[:groupPrefixLengthWords], " ")
			return ems, fmt.Errorf("wrong number of shares (%d supplied, %d required for group starting with %q)",
				len(group.shares), group.shares[0].memberThreshold, prefix)
		}

		i++
	}

	groupShares := make([]rawShare, 0, len(groups))
	for groupIndex, group := range groups {
		grs := groupRawShares(group)
		secret, err := recoverSecret(group.shares[0].memberThreshold, grs)
		if err != nil {
			return ems, err
		}
		/*
			fmt.Fprintf(os.Stderr,
				"recoverEMS: groupIndex %d, groupRawShares %v, secret %v\n",
				groupIndex, grs, secret)
		*/
		groupShares = append(groupShares, rawShare{
			x:    groupIndex,
			data: secret,
		})
	}
	/*
		fmt.Fprintf(os.Stderr,
			"recoverEMS: groupShares %v\n", groupShares)
	*/

	ciphertext, err := recoverSecret(params.groupThreshold, groupShares)
	if err != nil {
		return ems, err
	}

	return encryptedMasterSecret{
		identifier:        params.identifier,
		extendable:        params.extendable == 1,
		iterationExponent: params.iterationExponent,
		ciphertext:        ciphertext,
	}, nil
}

// CombineMnemonics combines mnemonics into the master secret which was
// originally split into shares using Shamir's Secret Sharing Scheme.
// The master secret may be optionally protected with a passphrase.
func CombineMnemonics(mnemonics []string, passphrase []byte) ([]byte, error) {
	if len(mnemonics) == 0 {
		return nil, errors.New("the list of mnemonics is empty")
	}

	groups, err := newShareGroupMap(mnemonics)
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(os.Stderr, "CombineMnemonics: %d mnemonic(s), %d group(s), %d share(s) in group 1\n", len(mnemonics), len(groups), len(groups[0].shares))
	ems, err := recoverEMS(groups)
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(os.Stderr, "CombineMnemonics: ems %v\n", ems)
	masterSecret, err := ems.decrypt(passphrase)
	if err != nil {
		return nil, err
	}

	return masterSecret, nil
}
